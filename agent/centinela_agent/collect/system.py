"""CPU, carga, memoria, procesos y tiempo encendido, leidos de /proc."""

from __future__ import annotations

import os

from ..util import read


def cpu_times() -> list | None:
    """Contadores acumulados de la linea «cpu» de /proc/stat."""
    raw = read("/proc/stat")
    if not raw:
        return None
    for line in raw.splitlines():
        if line.startswith("cpu "):
            vals = [int(x) for x in line.split()[1:]]
            return (vals + [0] * 10)[:10]
    return None


def cpu_percent(prev: list | None, cur: list | None) -> dict | None:
    """Uso entre dos lecturas. Steal importa en un VPS: es CPU que el anfitrion no nos da."""
    if not prev or not cur:
        return None
    d = [c - p for c, p in zip(cur, prev)]
    # guest y guest_nice ya van sumados en user y nice: no se cuentan dos veces.
    total = sum(d[:8])
    if total <= 0:
        return None
    idle = d[3] + d[4]
    return {
        "pct": round(100.0 * (total - idle) / total, 1),
        "iowait": round(100.0 * d[4] / total, 1),
        "steal": round(100.0 * d[7] / total, 1),
        "count": os.cpu_count() or 1,
    }


def meminfo() -> dict:
    out = {}
    raw = read("/proc/meminfo") or ""
    for line in raw.splitlines():
        k, _, v = line.partition(":")
        parts = v.split()
        if parts and parts[0].isdigit():
            out[k] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    return out


def memory() -> dict:
    m = meminfo()
    total = m.get("MemTotal", 0)
    avail = m.get("MemAvailable")
    if avail is None:  # nucleos anteriores a 3.14
        avail = m.get("MemFree", 0) + m.get("Buffers", 0) + m.get("Cached", 0)
    swap_total = m.get("SwapTotal", 0)
    swap_used = swap_total - m.get("SwapFree", 0)
    return {
        "mem": {
            "total": total,
            "available": avail,
            "pct": round(100.0 * (total - avail) / total, 1) if total else None,
        },
        "swap": {
            "total": swap_total,
            "used": swap_used,
            "pct": round(100.0 * swap_used / swap_total, 1) if swap_total else None,
        },
    }


def load() -> list:
    try:
        return [round(x, 2) for x in os.getloadavg()]
    except OSError:
        return []


def uptime() -> float | None:
    raw = read("/proc/uptime")
    try:
        return float(raw.split()[0]) if raw else None
    except (ValueError, IndexError):
        return None


def processes() -> dict:
    """Recuento por estado. D (espera de E/S no interrumpible) acumulandose es mala senal."""
    counts = {"total": 0, "running": 0, "blocked": 0, "zombie": 0}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return counts
    for pid in pids:
        raw = read("/proc/%s/stat" % pid)
        if not raw:
            continue  # termino mientras se recorria
        # El nombre del proceso va entre parentesis y puede contener espacios.
        state = raw[raw.rfind(")") + 2: raw.rfind(")") + 3]
        counts["total"] += 1
        if state == "R":
            counts["running"] += 1
        elif state == "D":
            counts["blocked"] += 1
        elif state == "Z":
            counts["zombie"] += 1
    return counts
