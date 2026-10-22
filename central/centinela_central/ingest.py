"""Entrada de informes: valida, guarda la serie, actualiza el estado y las alertas."""

from __future__ import annotations

import json

from . import alerts, db, health

KNOWN_SECTIONS = {"inventory", "services", "timesync", "raid", "zfs", "smart", "ipmi"}
MAX_REPORTS = 500
MAX_AGE = 8 * 86400     # la cola del agente guarda dos dias; mas atras es un reloj roto
MAX_AHEAD = 600
MAX_STATE = 2_000_000   # bytes de estado por servidor


class IngestError(Exception):
    pass


def _num(v):
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def series_row(m: dict) -> tuple:
    """Las columnas que se grafican, resumidas de las metricas completas."""
    cpu = m.get("cpu") if isinstance(m.get("cpu"), dict) else {}
    load = m.get("load") if isinstance(m.get("load"), list) else []
    fs = [f for f in (m.get("fs") or []) if isinstance(f, dict) and not f.get("ro")]
    pcts = [_num(f.get("pct")) for f in fs]
    pcts = [p for p in pcts if p is not None]
    temps = [_num((t or {}).get("c")) for t in (m.get("temps") or []) if isinstance(t, dict)]
    temps = [t for t in temps if t is not None]

    def total(items, key):
        vals = [_num((x or {}).get(key)) for x in (items or []) if isinstance(x, dict)]
        vals = [v for v in vals if v is not None]
        return sum(vals) if vals else None

    return (
        _num(cpu.get("pct")), _num(cpu.get("iowait")), _num(cpu.get("steal")),
        _num(load[0]) if load else None,
        _num((m.get("mem") or {}).get("pct")), _num((m.get("swap") or {}).get("pct")),
        max(pcts) if pcts else None,
        total(m.get("net"), "rx_bps"), total(m.get("net"), "tx_bps"),
        total(m.get("io"), "r_bps"), total(m.get("io"), "w_bps"),
        max(temps) if temps else None,
    )


def ingest(host, payload: dict, now: int, client_ip: str) -> dict:
    reports = payload.get("reports")
    if not isinstance(reports, list) or not reports:
        raise IngestError("no hay informes")
    if len(reports) > MAX_REPORTS:
        raise IngestError("demasiados informes en un envío (máx. %d)" % MAX_REPORTS)

    validos = []
    for r in reports:
        if not isinstance(r, dict):
            continue
        ts = r.get("ts")
        if not isinstance(ts, int) or ts < now - MAX_AGE or ts > now + MAX_AHEAD:
            continue
        validos.append(r)
    if not validos:
        raise IngestError("ningún informe válido (¿reloj del servidor desviado?)")
    validos.sort(key=lambda r: (r["ts"], r.get("seq", 0)))

    state = json.loads(host["state"] or "{}")
    secciones = state.setdefault("sections", {})
    rows = []
    interval = host["interval"]
    for r in validos:
        ts = r["ts"]
        m = r.get("metrics")
        if isinstance(m, dict):
            rows.append((host["id"], 0, ts) + series_row(m))
            if ts >= int(state.get("metrics_ts") or 0):
                state["metrics"], state["metrics_ts"] = m, ts
        for name, data in (r.get("sections") or {}).items():
            if name in KNOWN_SECTIONS and ts >= int((secciones.get(name) or {}).get("ts") or 0):
                secciones[name] = {"ts": ts, "data": data}
        if isinstance(r.get("interval"), int) and 15 <= r["interval"] <= 3600:
            interval = r["interval"]

    ultimo = validos[-1]
    errs = ultimo.get("errors")
    state["errors"] = {"ts": ultimo["ts"], "data": errs} if isinstance(errs, dict) and errs else {}
    # El desfase solo se mide con un informe recien hecho, no con los que esperaron en cola.
    skew = None if ultimo.get("spooled") else ultimo["ts"] - now

    raw = json.dumps(state, separators=(",", ":"))
    if len(raw) > MAX_STATE:
        raise IngestError("estado demasiado grande")

    inv = health.section(state, "inventory", now) or {}
    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    problems = health.evaluate(state, now, skew)

    with db.tx() as c:
        c.executemany(
            "INSERT OR REPLACE INTO series (host_id, res, ts, cpu, iowait, steal, load, mem, swap, disk, rx, tx, rd, wr, temp)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        c.execute(
            "UPDATE hosts SET last_seen = ?, last_ip = ?, agent_version = ?, interval = ?, skew = ?, state = ?,"
            " hostname = COALESCE(?, hostname) WHERE id = ?",
            (now, client_ip, str(agent.get("version") or host["agent_version"] or "")[:20], interval,
             skew if skew is not None else host["skew"], raw, inv.get("hostname"), host["id"]))
        alerts.sync(c, host["id"], problems, now, offline=False)
        # Informes atrasados (cola tras un corte): las medias ya calculadas de ese
        # tramo hay que rehacerlas.
        oldest = validos[0]["ts"]
        if oldest < now - 600:
            prev = db.meta_get("rollup_dirty")
            if prev is None or oldest < int(prev):
                db.meta_set(c, "rollup_dirty", oldest)
    return {"ok": True, "accepted": len(validos), "interval": interval}
