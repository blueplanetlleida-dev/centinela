"""Aplicacion web del central: API de los agentes y panel de la flota."""

from __future__ import annotations

import contextlib
import json
import logging
import secrets
import threading
import time
import zlib
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from . import VERSION, alerts, auth, db, fmt, ingest, rollup, views
from .bundle import Bundle
from .config import Config

log = logging.getLogger("centinela.central")
PKG = Path(__file__).resolve().parent

MAX_BODY = 8 * 1024 * 1024        # comprimido
MAX_JSON = 48 * 1024 * 1024       # descomprimido: tope contra bombas gzip
COOKIE = "cc_sess"
RANGES = {"6h": (6 * 3600, 0), "24h": (86400, 0), "7d": (7 * 86400, 1), "30d": (30 * 86400, 2), "1y": (365 * 86400, 2)}


class BodyError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status
        self.msg = msg


async def read_json(request: Request) -> dict:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY:
        raise BodyError(413, "envío demasiado grande")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            raise BodyError(413, "envío demasiado grande")
    raw = bytes(body)
    if request.headers.get("content-encoding", "").lower() == "gzip":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            raw = d.decompress(raw, MAX_JSON)
        except zlib.error:
            raise BodyError(400, "gzip inválido")
        if d.unconsumed_tail:
            raise BodyError(413, "contenido descomprimido demasiado grande")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise BodyError(400, "JSON inválido")
    if not isinstance(data, dict):
        raise BodyError(400, "se esperaba un objeto JSON")
    return data


def create_app(cfg: Config) -> FastAPI:
    db.init(cfg.db)
    bundle = Bundle(cfg.agent_src, cfg.public_url)
    if bundle.error:
        log.warning(bundle.error)

    templates = Jinja2Templates(directory=str(PKG / "templates"))
    env = templates.env
    env.filters.update(bytes=fmt.bytes_h, rate=fmt.rate_h, pct=fmt.pct_h, num=fmt.num_h,
                       duration=fmt.duration_h, ago=fmt.ago_h, dt=fmt.dt_h)
    env.globals.update(base=cfg.base_path, version=VERSION, status_label=views.status_label,
                       sev_label=views.sev_label, level=views.level)

    stop = threading.Event()

    def background():
        # Sin contacto, avisos por correo y reduccion de series. Un fallo aqui no
        # debe tumbar el servicio: se registra y se reintenta en la vuelta siguiente.
        next_roll = 0.0
        while not stop.wait(30):
            try:
                alerts.loop_once(cfg)
                if time.monotonic() >= next_roll:
                    rollup.run()
                    next_roll = time.monotonic() + 300
            except Exception:
                log.exception("fallo en la tarea de fondo")

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        t = threading.Thread(target=background, name="centinela-bg", daemon=True)
        t.start()
        yield
        stop.set()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    B = cfg.base_path
    app.mount(B + "/static", StaticFiles(directory=str(PKG / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "same-origin")
        h.setdefault("X-Frame-Options", "DENY")
        # Sin scripts en linea: script-src 'self' basta y no hace falta nonce.
        h.setdefault("Content-Security-Policy",
                     "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                     "script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; "
                     "base-uri 'none'; form-action 'self'")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.url.scheme == "https":
            h.setdefault("Strict-Transport-Security", "max-age=31536000")
        if not request.url.path.startswith(B + "/static/"):
            h.setdefault("Cache-Control", "no-store")
        return resp

    # ------------------------------------------------------------ utilidades

    def ip_of(request: Request) -> str:
        return request.client.host if request.client else "?"

    def session(request: Request):
        return auth.get_session(request.cookies.get(COOKIE), int(time.time()))

    def to_login(request: Request) -> RedirectResponse:
        nxt = request.url.path
        return RedirectResponse(B + "/login" + ("?next=" + nxt if nxt not in (B + "/", B) else ""), status_code=303)

    def page(request: Request, name: str, ctx: dict, status: int = 200) -> HTMLResponse:
        if ctx.get("s"):
            ctx.setdefault("top", views.top_counts())
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    async def form_with_csrf(request: Request, s) -> dict | None:
        form = await request.form()
        sent = str(form.get("csrf", ""))
        if not s or not secrets.compare_digest(sent, s["csrf"]):
            return None
        return form

    # ------------------------------------------------------------ API de agentes

    @app.get(B + "/healthz", include_in_schema=False)
    def healthz():
        return PlainTextResponse("ok")

    @app.post(B + "/api/v1/enroll")
    async def api_enroll(request: Request):
        now = int(time.time())
        ip = ip_of(request)
        if auth.too_many_fails(ip, now):
            return JSONResponse({"error": "demasiados intentos; espera unos minutos"}, status_code=429)
        try:
            data = await read_json(request)
        except BodyError as e:
            return JSONResponse({"error": e.msg}, status_code=e.status)
        res = await run_in_threadpool(views.enroll_agent, data, ip, now)
        if "error" in res:
            auth.record_fail(ip, now)
            return JSONResponse({"error": res["error"]}, status_code=403)
        return JSONResponse(res)

    @app.post(B + "/api/v1/report")
    async def api_report(request: Request):
        h = request.headers.get("authorization", "")
        token = h[7:].strip() if h.lower().startswith("bearer ") else ""
        host = await run_in_threadpool(auth.host_by_token, token)
        if host is None:
            return JSONResponse({"error": "agente no reconocido"}, status_code=401)
        try:
            data = await read_json(request)
        except BodyError as e:
            return JSONResponse({"error": e.msg}, status_code=e.status)
        try:
            res = await run_in_threadpool(ingest.ingest, host, data, int(time.time()), ip_of(request))
        except ingest.IngestError as e:
            return JSONResponse({"error": str(e)}, status_code=422)
        return JSONResponse(res)

    @app.get(B + "/dl/install.sh")
    def dl_install():
        if bundle.error:
            return PlainTextResponse("echo 'El central no tiene el paquete del agente: %s' >&2; exit 1\n" % bundle.error,
                                     status_code=503)
        return Response(bundle.install_script(), media_type="text/x-shellscript; charset=utf-8")

    @app.get(B + "/dl/centinela-agent.tar.gz")
    def dl_tar():
        if bundle.error:
            return PlainTextResponse(bundle.error, status_code=503)
        return Response(bundle.tar, media_type="application/gzip",
                        headers={"Content-Disposition": 'attachment; filename="centinela-agent-%s.tar.gz"' % bundle.version})

    # ------------------------------------------------------------ sesion

    @app.get(B + "/login", response_class=HTMLResponse)
    def login_form(request: Request, next: str = ""):
        if session(request):
            return RedirectResponse(B + "/", status_code=303)
        return page(request, "login.html", {"error": None, "next": next, "username": ""})

    @app.post(B + "/login", response_class=HTMLResponse)
    async def login_post(request: Request):
        form = await request.form()
        now = int(time.time())
        user, err = await run_in_threadpool(
            auth.login, str(form.get("username", "")), str(form.get("password", "")),
            str(form.get("code", "")), ip_of(request), now)
        nxt = str(form.get("next", ""))
        if user is None:
            return page(request, "login.html", {"error": err, "next": nxt, "username": str(form.get("username", ""))},
                        status=401)
        token = auth.create_session(user["id"], ip_of(request), now)
        # Solo rutas propias: un next=https://otro.sitio seria un redirector abierto.
        dest = nxt if nxt.startswith(B + "/") and not nxt.startswith("//") else B + "/"
        resp = RedirectResponse(dest, status_code=303)
        resp.set_cookie(COOKIE, token, httponly=True, samesite="lax", path=B or "/",
                        secure=request.url.scheme == "https", max_age=auth.SESSION_MAX)
        return resp

    @app.post(B + "/logout")
    async def logout(request: Request):
        s = session(request)
        if s and await form_with_csrf(request, s) is not None:
            auth.drop_session(request.cookies.get(COOKIE))
        resp = RedirectResponse(B + "/login", status_code=303)
        resp.delete_cookie(COOKIE, path=B or "/")
        return resp

    # ------------------------------------------------------------ panel

    @app.get(B + "/", response_class=HTMLResponse)
    def fleet(request: Request, f: str = ""):
        s = session(request)
        if not s:
            return to_login(request)
        return page(request, "fleet.html", {"s": s, **views.fleet(f)})

    @app.get(B + "/fragment/fleet", response_class=HTMLResponse)
    def fleet_fragment(request: Request, f: str = ""):
        s = session(request)
        if not s:
            return PlainTextResponse("sesión caducada", status_code=401)
        return page(request, "_fleet.html", {"s": s, **views.fleet(f)})

    @app.get(B + "/host/{hid}", response_class=HTMLResponse)
    def host_page(request: Request, hid: str):
        s = session(request)
        if not s:
            return to_login(request)
        v = views.host(hid)
        if v is None:
            return page(request, "notfound.html", {"s": s}, status=404)
        return page(request, "host.html", {"s": s, **v})

    @app.get(B + "/fragment/host/{hid}", response_class=HTMLResponse)
    def host_fragment(request: Request, hid: str):
        s = session(request)
        if not s:
            return PlainTextResponse("sesión caducada", status_code=401)
        v = views.host(hid)
        if v is None:
            return PlainTextResponse("no existe", status_code=404)
        return page(request, "_host_now.html", {"s": s, **v})

    @app.get(B + "/api/ui/host/{hid}/series")
    def host_series(request: Request, hid: str, range: str = "24h"):
        if not session(request):
            return JSONResponse({"error": "sesión caducada"}, status_code=401)
        if range not in RANGES:
            return JSONResponse({"error": "rango no válido"}, status_code=400)
        secs, res = RANGES[range]
        return JSONResponse(views.series(hid, secs, res))

    @app.post(B + "/host/{hid}/rename")
    async def host_rename(request: Request, hid: str):
        s = session(request)
        form = await form_with_csrf(request, s)
        if form is None:
            return to_login(request) if not s else PlainTextResponse("CSRF", status_code=403)
        await run_in_threadpool(views.rename_host, hid, str(form.get("name", "")), s["username"], ip_of(request))
        return RedirectResponse(B + "/host/" + hid, status_code=303)

    @app.post(B + "/host/{hid}/delete")
    async def host_delete(request: Request, hid: str):
        s = session(request)
        form = await form_with_csrf(request, s)
        if form is None:
            return to_login(request) if not s else PlainTextResponse("CSRF", status_code=403)
        await run_in_threadpool(views.delete_host, hid, s["username"], ip_of(request))
        return RedirectResponse(B + "/", status_code=303)

    @app.get(B + "/alerts", response_class=HTMLResponse)
    def alerts_page(request: Request):
        s = session(request)
        if not s:
            return to_login(request)
        return page(request, "alerts.html", {"s": s, **views.alerts_list()})

    @app.get(B + "/enroll", response_class=HTMLResponse)
    def enroll_page(request: Request):
        s = session(request)
        if not s:
            return to_login(request)
        return page(request, "enroll.html", {"s": s, "new_code": None, **views.enroll_info(cfg, bundle)})

    @app.post(B + "/enroll", response_class=HTMLResponse)
    async def enroll_post(request: Request):
        s = session(request)
        form = await form_with_csrf(request, s)
        if form is None:
            return to_login(request) if not s else PlainTextResponse("CSRF", status_code=403)
        try:
            horas = max(1, min(24 * 30, int(str(form.get("ttl", "24")))))
        except ValueError:
            horas = 24
        code = await run_in_threadpool(views.create_code, str(form.get("label", "")), horas * 3600,
                                       s["username"], ip_of(request))
        return page(request, "enroll.html", {"s": s, "new_code": code, "new_label": str(form.get("label", "")),
                                             **views.enroll_info(cfg, bundle)})

    @app.post(B + "/enroll/revoke")
    async def enroll_revoke(request: Request):
        s = session(request)
        form = await form_with_csrf(request, s)
        if form is None:
            return to_login(request) if not s else PlainTextResponse("CSRF", status_code=403)
        await run_in_threadpool(views.revoke_code, str(form.get("code_hash", "")), s["username"], ip_of(request))
        return RedirectResponse(B + "/enroll", status_code=303)

    if B:
        @app.get(B, include_in_schema=False)
        def base_redirect():
            return RedirectResponse(B + "/", status_code=307)

    return app
