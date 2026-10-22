"""Alertas: se abren, se actualizan y se cierran solas segun lo que digan las reglas.

El aviso por correo vive en mailer.py.
"""

from __future__ import annotations

import time

from . import db, mailer
from .fmt import ago_h
from .health import RANK


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


def loop_once(cfg) -> None:
    now = int(time.time())
    check_offline(cfg, now)
    mailer.notify_alerts(cfg, now)
    mailer.weekly_tick(cfg, now)
