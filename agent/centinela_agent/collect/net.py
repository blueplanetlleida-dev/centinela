"""Trafico y errores por interfaz fisica (las virtuales de Docker y puentes se omiten)."""

from __future__ import annotations

import os

from ..util import read


def _fisica(name: str) -> bool:
    if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr", "cali", "flannel", "cni")):
        return False
    return os.path.exists("/sys/class/net/%s/device" % name) or name.startswith(("bond", "team"))


def counters() -> dict:
    """Por interfaz: (rx_bytes, rx_errs, rx_drop, tx_bytes, tx_errs, tx_drop)."""
    out = {}
    raw = read("/proc/net/dev") or ""
    for line in raw.splitlines()[2:]:
        name, _, rest = line.partition(":")
        name = name.strip()
        if not _fisica(name):
            continue
        f = rest.split()
        if len(f) < 16:
            continue
        out[name] = (int(f[0]), int(f[2]), int(f[3]), int(f[8]), int(f[10]), int(f[11]))
    return out


def rates(prev: dict | None, cur: dict, dt: float) -> list:
    if not prev or dt <= 0:
        return []
    out = []
    for name, c in sorted(cur.items()):
        p = prev.get(name)
        if not p:
            continue
        d = [max(0, a - b) for a, b in zip(c, p)]
        out.append({
            "if": name,
            "rx_bps": int(d[0] / dt),
            "tx_bps": int(d[3] / dt),
            "errs": d[1] + d[4],
            "drops": d[2] + d[5],
            "state": (read("/sys/class/net/%s/operstate" % name) or "").strip() or None,
        })
    return out
