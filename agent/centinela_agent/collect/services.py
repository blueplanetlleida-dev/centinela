"""Unidades de systemd caidas y sincronizacion de la hora."""

from __future__ import annotations

import os

from ..util import run, which


def systemd_available() -> bool:
    return os.path.isdir("/run/systemd/system") and bool(which("systemctl"))


def services() -> dict:
    out = {"state": None, "failed": []}
    if not systemd_available():
        return out
    rc, txt = run(["systemctl", "is-system-running"], timeout=10)
    out["state"] = txt.strip() or None
    rc, txt = run(["systemctl", "list-units", "--state=failed", "--no-legend", "--plain", "--no-pager"], timeout=15)
    for line in txt.splitlines():
        f = line.split(None, 4)
        if f:
            out["failed"].append({"unit": f[0], "description": f[4] if len(f) > 4 else ""})
    return out


def timesync() -> dict:
    """¿Esta la hora sincronizada? Un reloj desviado rompe TLS, 2FA y la lectura de los logs."""
    if which("timedatectl"):
        rc, txt = run(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "NTP", "-p", "Timezone"], timeout=10)
        if rc == 0 and txt:
            kv = dict(line.split("=", 1) for line in txt.splitlines() if "=" in line)
            return {
                "synced": kv.get("NTPSynchronized") == "yes",
                "ntp_enabled": kv.get("NTP") == "yes",
                "timezone": kv.get("Timezone") or None,
            }
    if which("chronyc"):
        rc, txt = run(["chronyc", "-n", "tracking"], timeout=10)
        if rc == 0:
            return {"synced": "Not synchronised" not in txt, "ntp_enabled": True, "timezone": None}
    return {"synced": None, "ntp_enabled": None, "timezone": None}
