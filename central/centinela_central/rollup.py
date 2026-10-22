"""Reduccion de resolucion y caducidad de las series.

Cada informe se guarda tal cual 48 horas; despues quedan medias de 5 minutos
(35 dias) y de 1 hora (400 dias). Disco y temperatura guardan el maximo del
tramo, no la media: un pico de temperatura promediado deja de verse.
"""

from __future__ import annotations

import time

from . import db

RES = {1: 300, 2: 3600}
KEEP = {0: 48 * 3600, 1: 35 * 86400, 2: 400 * 86400}

AGG = ("AVG(cpu), AVG(iowait), AVG(steal), AVG(load), AVG(mem), AVG(swap), MAX(disk),"
       " AVG(rx), AVG(tx), AVG(rd), AVG(wr), MAX(temp)")


def _roll(c, res: int, desde: int, hasta: int) -> None:
    paso = RES[res]
    origen = res - 1
    c.execute(
        "INSERT OR REPLACE INTO series (host_id, res, ts, cpu, iowait, steal, load, mem, swap, disk, rx, tx, rd, wr, temp)"
        " SELECT host_id, ?, (ts / ?) * ?, " + AGG +
        " FROM series WHERE res = ? AND ts >= ? AND ts < ? GROUP BY host_id, (ts / ?)",
        (res, paso, paso, origen, desde, hasta, paso))


def run(now: int | None = None) -> None:
    now = now or int(time.time())
    sucio = db.meta_get("rollup_dirty")
    with db.tx() as c:
        for res, paso in RES.items():
            hasta = (now // paso) * paso          # el tramo en curso aun no esta completo
            marca = int(db.meta_get("rollup_%d" % res) or (hasta - 2 * 86400))
            desde = marca
            if sucio is not None:
                desde = min(desde, (int(sucio) // paso) * paso)
            # Hasta 8 dias atras puede llegar algo de una cola; mas alla no hay origen que rehacer.
            desde = max(desde, now - max(KEEP[res - 1], 8 * 86400))
            if desde < hasta:
                _roll(c, res, desde, hasta)
            db.meta_set(c, "rollup_%d" % res, hasta)
        c.execute("DELETE FROM meta WHERE key = 'rollup_dirty'")
        for res, keep in KEEP.items():
            c.execute("DELETE FROM series WHERE res = ? AND ts < ?", (res, now - keep))
        # Limpieza de lo que no hace falta guardar para siempre.
        c.execute("DELETE FROM alerts WHERE closed_at IS NOT NULL AND closed_at < ?", (now - 180 * 86400,))
        c.execute("DELETE FROM enroll_codes WHERE expires_at < ?", (now - 30 * 86400,))
        c.execute("DELETE FROM login_fail WHERE ts < ?", (now - 86400,))
        c.execute("DELETE FROM sessions WHERE seen_at < ? OR created_at < ?", (now - 12 * 3600, now - 7 * 86400))
        c.execute("DELETE FROM audit WHERE ts < ?", (now - 400 * 86400,))
