"""Formato para personas: tamanos, duraciones y fechas, en castellano."""

from __future__ import annotations

import time


def _dec(v: float, nd: int) -> str:
    s = ("%." + str(nd) + "f") % v
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s.replace(".", ",")


def bytes_h(v) -> str:
    if not isinstance(v, (int, float)):
        return "—"
    v = float(v)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(v) < 1024 or unit == "PB":
            return "%s %s" % (_dec(v, 0 if unit == "B" else 1), unit)
        v /= 1024
    return "—"


def rate_h(v) -> str:
    """Bytes por segundo."""
    return "—" if not isinstance(v, (int, float)) else bytes_h(v) + "/s"


def pct_h(v) -> str:
    return "—" if not isinstance(v, (int, float)) else _dec(v, 1) + " %"


def num_h(v, nd: int = 1) -> str:
    return "—" if not isinstance(v, (int, float)) else _dec(v, nd)


def duration_h(sec) -> str:
    if not isinstance(sec, (int, float)):
        return "—"
    sec = int(sec)
    if sec < 60:
        return "%d s" % sec
    if sec < 3600:
        return "%d min" % (sec // 60)
    if sec < 86400:
        h, m = divmod(sec // 60, 60)
        return "%d h %d min" % (h, m) if m else "%d h" % h
    d, h = divmod(sec // 3600, 24)
    return "%d d %d h" % (d, h) if h and d < 10 else "%d d" % d


def ago_h(ts, now: int | None = None) -> str:
    if not ts:
        return "nunca"
    now = now or int(time.time())
    diff = now - int(ts)
    if diff < 45:
        return "ahora"
    return "hace " + duration_h(diff)


def dt_h(ts) -> str:
    if not ts:
        return "—"
    return time.strftime("%d/%m/%Y %H:%M", time.localtime(int(ts)))
