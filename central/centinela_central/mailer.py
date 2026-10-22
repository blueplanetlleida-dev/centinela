"""Correo: avisos de alertas nuevas y resueltas, informe semanal y prueba.

Los mensajes van en HTML (con estilos en linea, que es lo unico que respetan
los clientes de correo) y con su version en texto plano.
"""

from __future__ import annotations

import logging
import re
import smtplib
import socket
import ssl
import subprocess
import time
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import db, fmt, settings
from .health import RANK

log = logging.getLogger("centinela.central")

EMAIL_RE = re.compile(r"^[^@\s<>,;\"']+@[^@\s<>,;\"']+\.[^@\s<>,;\"']+$")
SEV = {"crit": ("Crítico", "#b91c1c", "#fee2e2"), "warn": ("Aviso", "#b45309", "#fef3c7"),
       "info": ("Info", "#6B2F9A", "#F3ECFA")}

_env = Environment(loader=FileSystemLoader(str(Path(__file__).resolve().parent / "templates" / "mail")),
                   autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
_env.filters.update(bytes=fmt.bytes_h, pct=fmt.pct_h, num=fmt.num_h, duration=fmt.duration_h,
                    ago=fmt.ago_h, dt=fmt.dt_h)
_env.globals.update(SEV=SEV)

_fallo = {"at": 0.0}   # tras un fallo de envio, no reintentar en 10 minutos


class MailError(Exception):
    pass


def valid_email(addr: str) -> bool:
    return bool(EMAIL_RE.match(addr or "")) and len(addr) <= 254


def recipients(kind: str = "alert") -> list:
    col = "notify" if kind == "alert" else "weekly"
    out = []
    for r in db.conn().execute("SELECT email FROM users WHERE email IS NOT NULL AND email <> '' AND %s = 1" % col):
        out.append(r[0].strip())
    out += [a.strip() for a in settings.notify().get("extra_to") or []]
    vistos, final = set(), []
    for a in out:
        if valid_email(a) and a.lower() not in vistos:
            vistos.add(a.lower())
            final.append(a)
    return final


def send(cfg, to: list, subject: str, html: str, text: str) -> None:
    m = settings.mail(cfg)
    if not to:
        raise MailError("no hay destinatarios")
    remitente = m.get("from") or "centinela@" + socket.getfqdn()
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((m.get("from_name") or "Centinela", remitente))
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=remitente.split("@")[-1])
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    if m["method"] == "sendmail":
        binp = settings.sendmail_bin()
        if not binp:
            raise MailError("no hay sendmail en este servidor")
        try:
            p = subprocess.run([binp, "-t", "-i"], input=msg.as_bytes(), capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise MailError("sendmail: %s" % e)
        if p.returncode != 0:
            raise MailError("sendmail devolvió %d: %s" % (p.returncode, p.stderr.decode("utf-8", "replace")[:300]))
        return

    if not m["host"]:
        raise MailError("falta el servidor SMTP")
    ctx = ssl.create_default_context()
    try:
        if m["security"] == "ssl":
            smtp = smtplib.SMTP_SSL(m["host"], int(m["port"]), timeout=30, context=ctx)
        else:
            smtp = smtplib.SMTP(m["host"], int(m["port"]), timeout=30)
        with smtp:
            if m["security"] == "starttls":
                smtp.starttls(context=ctx)
            if m["user"]:
                smtp.login(m["user"], m["password"])
            smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        raise MailError("el servidor SMTP rechaza el usuario o la contraseña")
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        raise MailError("%s: %s" % (type(e).__name__, e))


def _record(ok: bool, detail: str) -> None:
    with db.tx() as c:
        db.meta_set(c, "mail_last", "%d|%s|%s" % (int(time.time()), "ok" if ok else "error", detail[:300]))


def last_status() -> dict | None:
    raw = db.meta_get("mail_last")
    if not raw:
        return None
    ts, st, detail = (raw.split("|", 2) + ["", ""])[:3]
    return {"ts": int(ts or 0), "ok": st == "ok", "detail": detail}


def _render(name: str, **ctx) -> str:
    return _env.get_template(name).render(**ctx)


# ------------------------------------------------------------------ avisos de alertas

def notify_alerts(cfg, now: int) -> None:
    n = settings.notify()
    m = settings.mail(cfg)
    to = recipients("alert")
    with db.tx() as w:
        # Lo que se abrio y se cerro antes de llegar a avisarse no merece correo.
        w.execute("UPDATE alerts SET notified = 2, notified_close = 2 WHERE notified = 0 AND closed_at IS NOT NULL")
        w.execute("UPDATE alerts SET notified_close = 2 WHERE closed_at IS NOT NULL AND notified <> 1 AND notified_close = 0")
        if not n["enabled"] or not settings.mail_ready(m) or not to:
            # Sin canal no hay a quien avisar; se marca para no inundar el dia que se configure.
            w.execute("UPDATE alerts SET notified = 2 WHERE notified = 0")
            w.execute("UPDATE alerts SET notified_close = 2 WHERE closed_at IS NOT NULL AND notified_close = 0")
            return
        # Por debajo de la gravedad elegida no se avisa (si luego empeora, sync la vuelve a poner en 0).
        if n["min_sev"] == "crit":
            w.execute("UPDATE alerts SET notified = 2 WHERE notified = 0 AND sev <> 'crit'")
        if not n["resolved"]:
            w.execute("UPDATE alerts SET notified_close = 2 WHERE closed_at IS NOT NULL AND notified_close = 0")

    if time.time() - _fallo["at"] < 600:
        return
    c = db.conn()
    nuevas = c.execute(
        "SELECT a.*, h.name FROM alerts a JOIN hosts h ON h.id = a.host_id"
        " WHERE a.closed_at IS NULL AND a.notified = 0 AND (a.key = 'offline' OR a.opened_at <= ?)"
        " ORDER BY a.sev = 'crit' DESC, h.name", (now - int(n["delay"]),)).fetchall()
    resueltas = c.execute(
        "SELECT a.*, h.name FROM alerts a JOIN hosts h ON h.id = a.host_id"
        " WHERE a.closed_at IS NOT NULL AND a.notified = 1 AND a.notified_close = 0 ORDER BY h.name").fetchall()
    if not nuevas and not resueltas:
        return

    por_host = {}
    for a in nuevas:
        por_host.setdefault((a["name"], a["host_id"]), []).append(a)
    ctx = {"nuevas": nuevas, "por_host": sorted(por_host.items(), key=lambda kv: (
               -max(RANK.get(x["sev"], 0) for x in kv[1]), kv[0][0].lower())),
           "resueltas": resueltas, "now": now, "url": cfg.public_url}
    try:
        send(cfg, to, _asunto(nuevas, resueltas), _render("alert.html", **ctx), _render("alert.txt", **ctx))
    except MailError as e:
        _fallo["at"] = time.time()
        log.error("no se pudo enviar el aviso por correo: %s", e)
        _record(False, str(e))
        return
    _record(True, "aviso: %d nuevo(s), %d resuelto(s)" % (len(nuevas), len(resueltas)))
    with db.tx() as w:
        w.executemany("UPDATE alerts SET notified = 1 WHERE id = ?", [(a["id"],) for a in nuevas])
        w.executemany("UPDATE alerts SET notified_close = 1 WHERE id = ?", [(a["id"],) for a in resueltas])


def _asunto(nuevas, resueltas) -> str:
    if nuevas:
        primero = nuevas[0]
        s = "%s: %s" % (primero["name"], primero["title"])
        if len(nuevas) > 1:
            s += " (y %d más)" % (len(nuevas) - 1)
        return "[Centinela] " + ("CRÍTICO · " if primero["sev"] == "crit" else "") + s
    return "[Centinela] Resuelto: %s" % ", ".join(sorted({a["name"] for a in resueltas}))


# ------------------------------------------------------------------ informe semanal

def weekly_data(now: int) -> dict:
    c = db.conn()
    desde = now - 7 * 86400
    hosts = []
    for h in c.execute("SELECT * FROM hosts ORDER BY name COLLATE NOCASE"):
        agg = c.execute(
            "SELECT AVG(cpu) cpu, AVG(mem) mem, MAX(disk) disk, MAX(temp) temp, COUNT(*) n"
            " FROM series WHERE host_id = ? AND res = 1 AND ts >= ?", (h["id"], desde)).fetchone()
        esperado = max(1, (now - max(desde, h["created_at"])) // 300)
        al = c.execute("SELECT SUM(sev = 'crit') crit, SUM(sev = 'warn') warn FROM alerts"
                       " WHERE host_id = ? AND opened_at >= ?", (h["id"], desde)).fetchone()
        hosts.append({
            "id": h["id"], "name": h["name"], "status": h["status"], "last_seen": h["last_seen"],
            "cpu": agg["cpu"], "mem": agg["mem"], "disk": agg["disk"], "temp": agg["temp"],
            "avail": min(100.0, 100.0 * (agg["n"] or 0) / esperado),
            "crit": al["crit"] or 0, "warn": al["warn"] or 0,
        })
    hosts.sort(key=lambda x: (-RANK.get(x["status"], 0), x["name"].lower()))
    abiertas = c.execute(
        "SELECT a.*, h.name FROM alerts a JOIN hosts h ON h.id = a.host_id WHERE a.closed_at IS NULL"
        " ORDER BY CASE a.sev WHEN 'crit' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, h.name").fetchall()
    semana = c.execute(
        "SELECT a.*, h.name FROM alerts a JOIN hosts h ON h.id = a.host_id WHERE a.opened_at >= ? AND a.sev <> 'info'"
        " ORDER BY CASE a.sev WHEN 'crit' THEN 0 ELSE 1 END, a.opened_at DESC LIMIT 30", (desde,)).fetchall()
    cuenta = {"total": len(hosts), "ok": 0, "warn": 0, "crit": 0, "offline": 0, "new": 0}
    for h in hosts:
        k = "ok" if h["status"] in ("ok", "info") else h["status"]
        cuenta[k] = cuenta.get(k, 0) + 1
    return {"hosts": hosts, "abiertas": abiertas, "semana": semana, "cuenta": cuenta, "desde": desde, "now": now}


def send_weekly(cfg, now: int, to: list | None = None) -> str:
    to = to or recipients("weekly")
    if not to:
        raise MailError("nadie recibe el informe semanal")
    data = weekly_data(now)
    ctx = dict(data, url=cfg.public_url)
    c = data["cuenta"]
    estado = ("%d sin contacto" % c["offline"] if c["offline"] else
              "%d crítico(s)" % c["crit"] if c["crit"] else
              "%d con avisos" % c["warn"] if c["warn"] else "todo bien")
    asunto = "[Centinela] Informe semanal: %d servidor(es), %s" % (c["total"], estado)
    send(cfg, to, asunto, _render("weekly.html", **ctx), _render("weekly.txt", **ctx))
    _record(True, "informe semanal a %d destinatario(s)" % len(to))
    return "Informe enviado a %s." % ", ".join(to)


def weekly_tick(cfg, now: int) -> None:
    n = settings.notify()
    if not n["weekly"]:
        return
    lt = time.localtime(now)
    if lt.tm_wday + 1 != int(n["weekly_day"]) or lt.tm_hour < int(n["weekly_hour"]):
        return
    semana = time.strftime("%G-%V", lt)
    if db.meta_get("weekly_last") == semana:
        return
    if not settings.mail_ready(settings.mail(cfg)) or not recipients("weekly"):
        return
    try:
        send_weekly(cfg, now)
    except MailError as e:
        log.error("no se pudo enviar el informe semanal: %s", e)
        _record(False, "informe semanal: %s" % e)
        return
    with db.tx() as w:
        db.meta_set(w, "weekly_last", semana)


# ------------------------------------------------------------------ prueba

def send_test(cfg, to: list) -> str:
    n = settings.notify()
    ctx = {"url": cfg.public_url, "n": n, "to": to, "alert_to": recipients("alert"),
           "weekly_to": recipients("weekly"), "now": int(time.time())}
    send(cfg, to, "[Centinela] Correo de prueba", _render("test.html", **ctx), _render("test.txt", **ctx))
    _record(True, "prueba a %s" % ", ".join(to))
    return "Enviado a %s. Si no llega en unos minutos, mira la carpeta de correo no deseado." % ", ".join(to)
