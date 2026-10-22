"""Alertas: se abren, se actualizan y se cierran solas segun lo que digan las reglas.

Y el aviso por correo, que agrupa en un solo mensaje todo lo pendiente y
espera a que un problema dure un poco antes de molestar.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from . import db
from .fmt import ago_h, duration_h
from .health import RANK

log = logging.getLogger("centinela.central")

SEV_TXT = {"crit": "CRÍTICO", "warn": "AVISO", "info": "INFO"}


def sync(c, host_id: str, problems: list, now: int, offline: bool) -> None:
    """Concilia las alertas abiertas de un servidor con los problemas actuales.

    offline=False: viene de un informe, asi que el servidor esta vivo (se cierra
    «offline») y la lista de problemas es completa. offline=True: solo se abre o
    se refresca la alerta de sin contacto; el resto queda como estaba.
    """
    abiertas = {r["key"]: r for r in c.execute(
        "SELECT * FROM alerts WHERE host_id = ? AND closed_at IS NULL", (host_id,))}
    actuales = {p["key"]: p for p in problems}

    for key, p in actuales.items():
        a = abiertas.get(key)
        if a is None:
            c.execute(
                "INSERT INTO alerts (host_id, key, sev, title, detail, opened_at, updated_at, notified)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (host_id, key, p["sev"], p["title"], p["detail"], now, now, 0 if p["sev"] in ("warn", "crit") else 2))
            continue
        empeora = RANK.get(p["sev"], 0) > RANK.get(a["sev"], 0)
        c.execute(
            "UPDATE alerts SET sev = ?, title = ?, detail = ?, updated_at = ?,"
            " notified = CASE WHEN ? THEN 0 ELSE notified END WHERE id = ?",
            (p["sev"], p["title"], p["detail"], now, 1 if empeora and p["sev"] in ("warn", "crit") else 0, a["id"]))

    if not offline:
        for key, a in abiertas.items():
            if key not in actuales:
                c.execute("UPDATE alerts SET closed_at = ?, updated_at = ? WHERE id = ?", (now, now, a["id"]))
    _status(c, host_id)


def _status(c, host_id: str) -> None:
    rows = c.execute("SELECT key, sev FROM alerts WHERE host_id = ? AND closed_at IS NULL", (host_id,)).fetchall()
    st = "ok"
    for r in rows:
        s = "offline" if r["key"] == "offline" else r["sev"]
        if RANK.get(s, 0) > RANK.get(st, 0):
            st = s
    c.execute("UPDATE hosts SET status = ? WHERE id = ? AND last_seen IS NOT NULL", (st, host_id))


def check_offline(cfg, now: int) -> None:
    """Abre «sin contacto» en los servidores que han dejado de informar."""
    hosts = db.conn().execute(
        "SELECT id, last_seen, interval FROM hosts WHERE last_seen IS NOT NULL AND token_hash IS NOT NULL").fetchall()
    for h in hosts:
        limite = max(cfg.offline_after, 3 * int(h["interval"] or 60))
        silencio = now - int(h["last_seen"])
        if silencio <= limite:
            continue
        p = {"key": "offline", "sev": "crit", "title": "Sin contacto",
             "detail": "Último informe %s. Puede estar apagado, sin red, o el agente parado "
                       "(systemctl status centinela-agent)." % ago_h(h["last_seen"], now)}
        with db.tx() as c:
            sync(c, h["id"], [p], now, offline=True)


def notify(cfg, now: int) -> None:
    c = db.conn()
    if not cfg.smtp_enabled:
        # Sin canal no hay a quien avisar; se marca para no inundar el dia que se configure.
        with db.tx() as w:
            w.execute("UPDATE alerts SET notified = 2 WHERE notified = 0")
            w.execute("UPDATE alerts SET notified_close = 2 WHERE closed_at IS NOT NULL AND notified_close = 0")
        return

    with db.tx() as w:
        # Lo que se abrio y se cerro antes de llegar a avisarse no merece correo.
        w.execute("UPDATE alerts SET notified = 2, notified_close = 2 WHERE notified = 0 AND closed_at IS NOT NULL")
        w.execute("UPDATE alerts SET notified_close = 2 WHERE closed_at IS NOT NULL AND notified <> 1 AND notified_close = 0")

    nuevas = c.execute(
        "SELECT a.*, h.name FROM alerts a JOIN hosts h ON h.id = a.host_id"
        " WHERE a.closed_at IS NULL AND a.notified = 0 AND (a.key = 'offline' OR a.opened_at <= ?)"
        " ORDER BY a.sev = 'crit' DESC, h.name", (now - cfg.notify_after,)).fetchall()
    resueltas = c.execute(
        "SELECT a.*, h.name FROM alerts a JOIN hosts h ON h.id = a.host_id"
        " WHERE a.closed_at IS NOT NULL AND a.notified = 1 AND a.notified_close = 0 ORDER BY h.name").fetchall()
    if not nuevas and not resueltas:
        return

    asunto = _asunto(nuevas, resueltas)
    lineas = []
    if nuevas:
        lineas.append("Problemas:\n")
        for a in nuevas:
            lineas.append("  [%s] %s: %s" % (SEV_TXT.get(a["sev"], a["sev"]), a["name"], a["title"]))
            if a["detail"]:
                lineas.append("      %s" % a["detail"])
            lineas.append("      desde %s" % ago_h(a["opened_at"], now))
        lineas.append("")
    if resueltas:
        lineas.append("Resueltos:\n")
        for a in resueltas:
            lineas.append("  %s: %s (duró %s)" % (a["name"], a["title"], duration_h(a["closed_at"] - a["opened_at"])))
        lineas.append("")
    if cfg.public_url:
        lineas.append("Panel: %s/" % cfg.public_url)

    try:
        send_mail(cfg, asunto, "\n".join(lineas))
    except (OSError, smtplib.SMTPException) as e:
        log.error("no se pudo enviar el aviso por correo: %s", e)
        return
    with db.tx() as w:
        w.executemany("UPDATE alerts SET notified = 1 WHERE id = ?", [(a["id"],) for a in nuevas])
        w.executemany("UPDATE alerts SET notified_close = 1 WHERE id = ?", [(a["id"],) for a in resueltas])


def _asunto(nuevas, resueltas) -> str:
    if nuevas:
        primero = nuevas[0]
        resto = len(nuevas) - 1
        s = "%s: %s" % (primero["name"], primero["title"])
        if resto:
            s += " (y %d más)" % resto
        return "[Centinela] " + s
    return "[Centinela] Resuelto: %s" % ", ".join(sorted({a["name"] for a in resueltas}))


def send_mail(cfg, subject: str, body: str) -> None:
    s = cfg.smtp
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = s["from"]
    msg["To"] = ", ".join(s["to"])
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=s["from"].split("@")[-1] or None)
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if s["port"] == 465:
        with smtplib.SMTP_SSL(s["host"], s["port"], timeout=30, context=ctx) as smtp:
            if s["user"]:
                smtp.login(s["user"], s["password"])
            smtp.send_message(msg)
        return
    with smtplib.SMTP(s["host"], s["port"], timeout=30) as smtp:
        if s["starttls"]:
            smtp.starttls(context=ctx)
        if s["user"]:
            smtp.login(s["user"], s["password"])
        smtp.send_message(msg)


def loop_once(cfg) -> None:
    now = int(time.time())
    check_offline(cfg, now)
    notify(cfg, now)
