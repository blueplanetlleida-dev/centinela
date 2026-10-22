"""Datos ya preparados para las plantillas y operaciones del panel."""

from __future__ import annotations

import json
import os
import re
import secrets
import time

from . import auth, db, health

STATUS = {
    "ok": ("ok", "Bien", "check"),
    "info": ("ok", "Bien", "check"),
    "warn": ("warn", "Aviso", "triangle-alert"),
    "crit": ("bad", "Crítico", "circle-alert"),
    "offline": ("bad", "Sin contacto", "wifi-off"),
    "new": ("muted", "Esperando", "clock"),
}
SEV = {"crit": ("bad", "Crítico"), "warn": ("warn", "Aviso"), "info": ("accent", "Info")}
VIRT = {
    "none": "Físico", "kvm": "Máquina virtual (KVM)", "qemu": "Máquina virtual (QEMU)",
    "vmware": "Máquina virtual (VMware)", "microsoft": "Máquina virtual (Hyper-V)", "xen": "Máquina virtual (Xen)",
    "oracle": "Máquina virtual (VirtualBox)", "amazon": "Máquina virtual (AWS)", "lxc": "Contenedor LXC",
    "openvz": "Contenedor OpenVZ", "docker": "Contenedor Docker", "wsl": "WSL",
}
PANELS = {"plesk": "Plesk", "hestia": "HestiaCP", "cpanel": "cPanel", "directadmin": "DirectAdmin"}


def status_label(st: str) -> tuple:
    return STATUS.get(st, STATUS["new"])


def sev_label(sev: str) -> tuple:
    return SEV.get(sev, SEV["info"])


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def level(pct, warn: float = 90, crit: float = 95) -> str:
    if pct is None:
        return "none"
    return "bad" if pct >= crit else "warn" if pct >= warn else "ok"


def top_counts() -> dict:
    c = db.conn()
    r = c.execute(
        "SELECT SUM(a.sev = 'crit' AND a.key <> 'offline') crit, SUM(a.sev = 'warn') warn, SUM(a.key = 'offline') offline"
        " FROM alerts a WHERE a.closed_at IS NULL").fetchone()
    return {"crit": r["crit"] or 0, "warn": r["warn"] or 0, "offline": r["offline"] or 0}


def _open_alerts(host_id: str | None = None) -> dict:
    sql = ("SELECT * FROM alerts WHERE closed_at IS NULL" + (" AND host_id = ?" if host_id else "") +
           " ORDER BY CASE sev WHEN 'crit' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, key = 'offline' DESC, opened_at")
    out = {}
    for a in db.conn().execute(sql, (host_id,) if host_id else ()):
        out.setdefault(a["host_id"], []).append(a)
    return out


def _summary(st: dict, now: int) -> dict:
    m = st.get("metrics") or {}
    inv = health.section(st, "inventory", now) or {}
    fs = [f for f in (m.get("fs") or []) if isinstance(f, dict) and _num(f.get("pct")) is not None and not f.get("ro")]
    peor = max(fs, key=lambda f: f["pct"]) if fs else None
    temps = [t for t in (m.get("temps") or []) if isinstance(t, dict) and _num(t.get("c")) is not None]
    tmax = max(temps, key=lambda t: t["c"]) if temps else None
    cpu = m.get("cpu") or {}
    load = m.get("load") or []
    return {
        "cpu": _num(cpu.get("pct")),
        "cores": _num(cpu.get("count")) or _num(inv.get("cpus")),
        "mem": _num((m.get("mem") or {}).get("pct")),
        "disk": _num(peor["pct"]) if peor else None,
        "disk_mount": peor["mount"] if peor else "",
        "temp": _num(tmax["c"]) if tmax else None,
        "temp_label": ("%s %s" % (tmax.get("chip", ""), tmax.get("label", ""))).strip() if tmax else "",
        "load": [_num(x) for x in load[:3]],
        "uptime": _num(m.get("uptime")),
        "os": (inv.get("os") or {}).get("name", ""),
        "virt": VIRT.get(inv.get("virt", ""), inv.get("virt", "")),
        "physical": inv.get("virt") == "none",
        "panel": PANELS.get(inv.get("panel") or "", ""),
    }


FILTERS = {"offline": "sin contacto", "crit": "críticos", "warn": "con avisos", "ok": "bien"}


def fleet(filtro: str = "") -> dict:
    now = int(time.time())
    filtro = filtro if filtro in FILTERS else ""
    abiertas = _open_alerts()
    rows = []
    for h in db.conn().execute("SELECT * FROM hosts ORDER BY name COLLATE NOCASE"):
        st = json.loads(h["state"] or "{}")
        al = abiertas.get(h["id"], [])
        rows.append({
            "id": h["id"], "name": h["name"], "hostname": h["hostname"] or "", "status": h["status"],
            "last_seen": h["last_seen"], "alerts": al,
            "problem": al[0] if al else None, **_summary(st, now),
        })
    rows.sort(key=lambda r: (-health.RANK.get(r["status"], 0), r["name"].lower()))
    counts = {"total": len(rows), "ok": 0, "warn": 0, "crit": 0, "offline": 0, "new": 0}
    for r in rows:
        r["group"] = "ok" if r["status"] in ("ok", "info") else r["status"]
        counts[r["group"]] = counts.get(r["group"], 0) + 1
    if filtro:
        rows = [r for r in rows if r["group"] == filtro]
    return {"hosts": rows, "counts": counts, "now": now, "nav": "fleet",
            "filtro": filtro, "filtro_txt": FILTERS.get(filtro, "")}


def host(hid: str) -> dict | None:
    h = db.conn().execute("SELECT * FROM hosts WHERE id = ?", (hid,)).fetchone()
    if h is None:
        return None
    now = int(time.time())
    st = json.loads(h["state"] or "{}")
    m = st.get("metrics") or {}
    sec = {name: health.section(st, name, now) for name in ("inventory", "services", "timesync", "raid", "zfs", "smart", "ipmi")}
    inv = sec["inventory"] or {}
    historial = db.conn().execute(
        "SELECT * FROM alerts WHERE host_id = ? AND closed_at IS NOT NULL ORDER BY closed_at DESC LIMIT 15", (hid,)).fetchall()
    return {
        "h": h, "now": now, "nav": "fleet", "st": st, "m": m, "sec": sec, "inv": inv,
        "sum": _summary(st, now),
        "alerts": _open_alerts(hid).get(hid, []),
        "history": historial,
        "fs": [f for f in (m.get("fs") or []) if isinstance(f, dict)],
        "net": [n for n in (m.get("net") or []) if isinstance(n, dict)],
        "io": [d for d in (m.get("io") or []) if isinstance(d, dict)],
        "temps": [t for t in (m.get("temps") or []) if isinstance(t, dict)],
        "fans": [f for f in (m.get("fans") or []) if isinstance(f, dict)],
        "errors": (st.get("errors") or {}).get("data") or {},
        "virt": VIRT.get(inv.get("virt", ""), inv.get("virt", "")),
        "panel": PANELS.get(inv.get("panel") or "", ""),
    }


COLS = ("cpu", "iowait", "steal", "load", "mem", "swap", "disk", "rx", "tx", "rd", "wr", "temp")
STEP = {1: 300, 2: 3600}


def series(hid: str, secs: int, res: int) -> dict:
    now = int(time.time())
    desde = now - secs
    h = db.conn().execute("SELECT interval FROM hosts WHERE id = ?", (hid,)).fetchone()
    if h is None:
        return {"error": "no existe"}
    rows = []
    corte = desde
    # La resolucion pedida y, para el tramo que aun no se ha resumido, las mas finas.
    for r in range(res, -1, -1):
        nuevos = db.conn().execute(
            "SELECT ts, " + ", ".join(COLS) + " FROM series WHERE host_id = ? AND res = ? AND ts >= ? ORDER BY ts",
            (hid, r, corte)).fetchall()
        rows.extend(nuevos)
        if nuevos:
            corte = nuevos[-1]["ts"] + STEP.get(r, 1)
    rows.sort(key=lambda x: x["ts"])
    return {
        "from": desde, "to": now,
        "step": STEP.get(res) or int(h["interval"] or 60),
        "ts": [r["ts"] for r in rows],
        "cols": {c: [r[c] for r in rows] for c in COLS},
    }


def alerts_list() -> dict:
    c = db.conn()
    q = ("SELECT a.*, h.name FROM alerts a JOIN hosts h ON h.id = a.host_id WHERE {} "
         "ORDER BY {} LIMIT 200")
    abiertas = c.execute(q.format("a.closed_at IS NULL",
                                  "CASE a.sev WHEN 'crit' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, a.opened_at")).fetchall()
    cerradas = c.execute(q.format("a.closed_at IS NOT NULL AND a.closed_at > %d" % (int(time.time()) - 7 * 86400),
                                  "a.closed_at DESC")).fetchall()
    return {"open": abiertas, "closed": cerradas, "now": int(time.time()), "nav": "alerts"}


# ------------------------------------------------------------ altas

def enroll_info(cfg, bundle) -> dict:
    now = int(time.time())
    codes = db.conn().execute(
        "SELECT e.*, h.name AS host_name FROM enroll_codes e LEFT JOIN hosts h ON h.id = e.host_id"
        " WHERE e.created_at > ? ORDER BY e.created_at DESC LIMIT 30", (now - 14 * 86400,)).fetchall()
    return {
        "codes": codes, "now": now, "nav": "enroll",
        "public_url": cfg.public_url, "bundle_ok": not bundle.error, "bundle_error": bundle.error,
        "bundle_version": bundle.version, "bundle_sha": bundle.sha256,
    }


def create_code(label: str, ttl: int, user: str, ip: str) -> str:
    now = int(time.time())
    code = auth.new_enroll_code()
    with db.tx() as c:
        c.execute("INSERT INTO enroll_codes (code_hash, label, created_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?)",
                  (auth.sha256(auth.norm_code(code)), label.strip()[:80], now, now + ttl, user))
        db.audit(c, now, user, ip, "enroll-code", "label=%s ttl=%d" % (label.strip()[:80], ttl))
    return code


def revoke_code(code_hash: str, user: str, ip: str) -> None:
    now = int(time.time())
    with db.tx() as c:
        c.execute("UPDATE enroll_codes SET expires_at = ? WHERE code_hash = ? AND used_at IS NULL", (now - 1, code_hash))
        db.audit(c, now, user, ip, "enroll-revoke", code_hash[:12])


def enroll_agent(data: dict, ip: str, now: int) -> dict:
    code = auth.norm_code(str(data.get("code", "")))
    if len(code) != 12:
        return {"error": "código de alta no válido"}
    row = db.conn().execute("SELECT * FROM enroll_codes WHERE code_hash = ?", (auth.sha256(code),)).fetchone()
    if row is None or row["used_at"] or row["expires_at"] < now:
        return {"error": "código de alta no válido, caducado o ya usado"}

    mid = str(data.get("machine_id") or "")[:64]
    hostname = str(data.get("hostname") or "")[:255]
    pedido = str(data.get("name") or "").strip()[:80]
    inv = data.get("inventory") if isinstance(data.get("inventory"), dict) else None
    token = auth.new_agent_token()
    replaced = False
    with db.tx() as c:
        prev = c.execute("SELECT * FROM hosts WHERE machine_id = ? AND machine_id <> ''", (mid,)).fetchone() if mid else None
        if prev is not None:
            # Misma maquina reinstalada: conserva historial y nombre; el token viejo deja de valer.
            hid, replaced = prev["id"], True
            name = pedido or prev["name"]
            c.execute("UPDATE hosts SET token_hash = ?, hostname = ?, name = ? WHERE id = ?",
                      (auth.sha256(token), hostname or prev["hostname"], name, hid))
        else:
            hid = secrets.token_hex(6)
            name = pedido or row["label"] or hostname or "servidor"
            state = {"sections": {"inventory": {"ts": now, "data": inv}}} if inv else {}
            c.execute("INSERT INTO hosts (id, name, hostname, machine_id, token_hash, created_at, status, state)"
                      " VALUES (?, ?, ?, ?, ?, ?, 'new', ?)",
                      (hid, name, hostname, mid, auth.sha256(token), now, json.dumps(state)))
        c.execute("UPDATE enroll_codes SET used_at = ?, host_id = ? WHERE code_hash = ?", (now, hid, row["code_hash"]))
        db.audit(c, now, None, ip, "enroll", "host=%s name=%s replaced=%s" % (hid, name, replaced))
    return {"agent_id": hid, "token": token, "name": name, "interval": 60, "replaced": replaced}


def rename_host(hid: str, name: str, user: str, ip: str) -> None:
    name = " ".join(name.split())[:80]
    if not name:
        return
    now = int(time.time())
    with db.tx() as c:
        c.execute("UPDATE hosts SET name = ? WHERE id = ?", (name, hid))
        db.audit(c, now, user, ip, "rename", "host=%s name=%s" % (hid, name))


def delete_host(hid: str, user: str, ip: str) -> None:
    now = int(time.time())
    with db.tx() as c:
        h = c.execute("SELECT name FROM hosts WHERE id = ?", (hid,)).fetchone()
        c.execute("DELETE FROM series WHERE host_id = ?", (hid,))
        c.execute("DELETE FROM alerts WHERE host_id = ?", (hid,))
        c.execute("DELETE FROM hosts WHERE id = ?", (hid,))
        db.audit(c, now, user, ip, "delete", "host=%s name=%s" % (hid, h["name"] if h else "?"))


# ------------------------------------------------------------ ajustes de avisos

TIMEZONES = ("Europe/Madrid", "Atlantic/Canary", "Europe/Lisbon", "Europe/London", "Europe/Paris", "UTC",
             "America/Mexico_City", "America/Bogota", "America/Argentina/Buenos_Aires")
DAYS = ("lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo")


class FormError(Exception):
    pass


def update_status(cfg) -> dict | None:
    """Lo que dejo el actualizador diario del central (update.sh)."""
    try:
        with open(os.path.join(os.path.dirname(cfg.db), "update.json"), "r", encoding="utf-8") as f:
            v = json.load(f)
        return v if isinstance(v, dict) else None
    except (OSError, ValueError):
        return None


def user_email(uid: int) -> str:
    r = db.conn().execute("SELECT email FROM users WHERE id = ?", (uid,)).fetchone()
    return (r["email"] or "") if r else ""


def notify_info(cfg) -> dict:
    from . import mailer, settings
    m = settings.mail(cfg)
    n = settings.notify()
    sin_correo = [r["username"] for r in db.conn().execute(
        "SELECT username FROM users WHERE (email IS NULL OR email = '') AND (notify = 1 OR weekly = 1)")]
    return {
        "nav": "notify",
        "mail": dict(m, password=""), "has_password": bool(m.get("password")),
        "notify": n, "ready": settings.mail_ready(m),
        "sendmail": settings.sendmail_bin(),
        "alert_to": mailer.recipients("alert"), "weekly_to": mailer.recipients("weekly"),
        "sin_correo": sin_correo, "last": mailer.last_status(),
        "timezones": TIMEZONES if n["timezone"] in TIMEZONES else TIMEZONES + (n["timezone"],),
        "days": DAYS, "from_conf": bool(cfg.smtp.get("host")) and not settings.get("mail", settings.MAIL_DEFAULT)["host"],
    }


def parse_notify_form(form) -> tuple:
    from . import mailer, settings

    def entero(name, lo, hi, default):
        try:
            v = int(str(form.get(name, default)).strip())
        except ValueError:
            raise FormError("Valor no válido en «%s»." % name)
        if not lo <= v <= hi:
            raise FormError("«%s» tiene que estar entre %d y %d." % (name, lo, hi))
        return v

    actual = settings.get("mail", settings.MAIL_DEFAULT)
    method = str(form.get("method", "smtp"))
    if method not in ("smtp", "sendmail"):
        raise FormError("Método de envío no válido.")
    security = str(form.get("security", "starttls"))
    if security not in ("starttls", "ssl", "none"):
        raise FormError("Seguridad no válida.")
    host = str(form.get("host", "")).strip()
    if host and not re.match(r"^[A-Za-z0-9.-]{1,253}$", host):
        raise FormError("Servidor SMTP no válido.")
    if method == "smtp" and not host:
        raise FormError("Falta el servidor SMTP (o elige el sendmail del propio servidor).")
    remitente = str(form.get("from", "")).strip()
    if remitente and not mailer.valid_email(remitente):
        raise FormError("La dirección del remitente no es válida.")
    password = str(form.get("password", ""))
    if not password and not form.get("clear_password"):
        password = actual.get("password", "")       # en blanco: se conserva la que habia
    mail_cfg = {
        "method": method, "host": host, "port": entero("port", 1, 65535, 587), "security": security,
        "user": str(form.get("user", "")).strip()[:200], "password": password[:200],
        "from": remitente, "from_name": " ".join(str(form.get("from_name", "Centinela")).split())[:60] or "Centinela",
    }
    extra = [a.strip() for a in re.split(r"[\s,;]+", str(form.get("extra_to", ""))) if a.strip()]
    malas = [a for a in extra if not mailer.valid_email(a)]
    if malas:
        raise FormError("Direcciones no válidas: %s" % ", ".join(malas[:5]))
    tz = str(form.get("timezone", "Europe/Madrid")).strip()
    if not re.match(r"^[A-Za-z0-9_+/-]{1,64}$", tz) or ".." in tz or not os.path.isfile(os.path.join("/usr/share/zoneinfo", tz)):
        raise FormError("Zona horaria desconocida.")
    min_sev = str(form.get("min_sev", "warn"))
    notify_cfg = {
        "enabled": bool(form.get("enabled")),
        "min_sev": min_sev if min_sev in ("warn", "crit") else "warn",
        "resolved": bool(form.get("resolved")),
        "delay": entero("delay", 0, 1440, 5) * 60,
        "extra_to": extra[:50],
        "weekly": bool(form.get("weekly")),
        "weekly_day": entero("weekly_day", 1, 7, 1),
        "weekly_hour": entero("weekly_hour", 0, 23, 8),
        "timezone": tz,
    }
    return mail_cfg, notify_cfg
