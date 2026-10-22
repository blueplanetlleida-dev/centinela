"""Ajustes que se cambian desde el panel: correo saliente, avisos e informe semanal.

Viven en la base de datos (tabla settings, JSON por clave). La seccion [smtp]
de central.conf sigue valiendo como punto de partida: si el panel aun no tiene
correo configurado, se usa la del fichero.
"""

from __future__ import annotations

import json
import os
import time

from . import db

MAIL_DEFAULT = {
    "method": "smtp",        # smtp | sendmail
    "host": "",
    "port": 587,
    "security": "starttls",  # starttls | ssl | none
    "user": "",
    "password": "",
    "from": "",
    "from_name": "Centinela",
}

NOTIFY_DEFAULT = {
    "enabled": True,
    "min_sev": "warn",       # warn: avisos y criticos; crit: solo criticos
    "resolved": True,        # avisar tambien cuando se resuelve
    "delay": 300,            # segundos que tiene que durar un problema antes de avisar
    "extra_to": [],          # direcciones que no son usuarios del panel
    "weekly": True,
    "weekly_day": 1,         # 1 = lunes ... 7 = domingo
    "weekly_hour": 8,
    "timezone": "Europe/Madrid",
}


def get(key: str, default: dict) -> dict:
    row = db.conn().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    out = dict(default)
    if row:
        try:
            val = json.loads(row[0])
            if isinstance(val, dict):
                out.update({k: v for k, v in val.items() if k in default})
        except ValueError:
            pass
    return out


def put(key: str, value: dict, user: str | None = None, ip: str | None = None) -> None:
    with db.tx() as c:
        c.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                  (key, json.dumps(value)))
        resumen = {k: ("***" if k == "password" and v else v) for k, v in value.items()}
        db.audit(c, int(time.time()), user, ip, "settings:" + key, json.dumps(resumen)[:480])


def mail(cfg) -> dict:
    """Correo saliente: el del panel si esta configurado; si no, el de central.conf."""
    m = get("mail", MAIL_DEFAULT)
    if m["method"] == "sendmail" or m["host"]:
        return m
    s = cfg.smtp
    if s.get("host"):
        return dict(MAIL_DEFAULT, host=s["host"], port=s["port"], user=s["user"], password=s["password"],
                    security="ssl" if s["port"] == 465 else ("starttls" if s["starttls"] else "none"),
                    **{"from": s["from"]})
    return m


def mail_ready(m: dict) -> bool:
    if m["method"] == "sendmail":
        return bool(sendmail_bin())
    return bool(m["host"])


def sendmail_bin() -> str | None:
    for p in ("/usr/sbin/sendmail", "/usr/lib/sendmail", "/usr/bin/sendmail"):
        if os.access(p, os.X_OK):
            return p
    return None


def notify() -> dict:
    return get("notify", NOTIFY_DEFAULT)


def apply_timezone() -> None:
    """La hora del panel, de los correos y del informe semanal sale de este ajuste."""
    tz = notify().get("timezone") or ""
    if tz and os.path.exists(os.path.join("/usr/share/zoneinfo", tz)):
        os.environ["TZ"] = tz
        time.tzset()
