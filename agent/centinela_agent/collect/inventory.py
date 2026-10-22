"""Inventario: que maquina es, que sistema lleva y que tiene pendiente.

Cambia poco, asi que se recoge al arrancar y cada pocas horas.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import sys
import time

from .. import VERSION
from ..util import read, run, which
from . import system


def os_release() -> dict:
    out = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        raw = read(path)
        if not raw:
            continue
        for line in raw.splitlines():
            k, sep, v = line.partition("=")
            if sep:
                out[k.strip()] = v.strip().strip('"').strip("'")
        break
    return {
        "id": out.get("ID", ""),
        "version": out.get("VERSION_ID", ""),
        "name": out.get("PRETTY_NAME") or out.get("NAME") or platform.system(),
        "like": out.get("ID_LIKE", ""),
    }


def virtualization() -> str:
    if which("systemd-detect-virt"):
        rc, out = run(["systemd-detect-virt"], timeout=5)
        return out.strip() or "none"
    return "unknown"


def cpu_model() -> str:
    raw = read("/proc/cpuinfo") or ""
    for line in raw.splitlines():
        k, _, v = line.partition(":")
        if k.strip() in ("model name", "Model", "Hardware", "cpu model"):
            return " ".join(v.split())
    return platform.processor() or ""


def addresses() -> list:
    rc, out = run(["ip", "-j", "addr"], timeout=5)
    if rc != 0:
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return []
    ips = []
    for iface in data:
        name = iface.get("ifname", "")
        if name == "lo" or name.startswith(("veth", "docker", "br-")):
            continue
        for a in iface.get("addr_info", []):
            if a.get("scope") == "global":
                ips.append({"if": name, "addr": a.get("local"), "prefix": a.get("prefixlen")})
    return ips


def panel() -> str | None:
    if os.path.exists("/usr/local/psa/version"):
        return "plesk"
    if os.path.isdir("/usr/local/hestia"):
        return "hestia"
    if os.path.exists("/usr/local/cpanel/version"):
        return "cpanel"
    if os.path.isdir("/usr/local/directadmin"):
        return "directadmin"
    return None


def pending_updates() -> dict:
    """Paquetes por actualizar, con los de seguridad aparte. Usa la cache que ya tenga el sistema."""
    if which("apt-get"):
        rc, out = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], timeout=90)
        if rc == 0:
            inst = [l for l in out.splitlines() if l.startswith("Inst ")]
            sec = [l for l in inst if "-security" in l]
            return {"manager": "apt", "total": len(inst), "security": len(sec)}
        return {"manager": "apt", "total": None, "security": None}
    for mgr in ("dnf", "yum"):
        if which(mgr):
            rc, out = run([mgr, "-q", "--cacheonly", "check-update"], timeout=90)
            # check-update devuelve 100 cuando hay actualizaciones y 0 cuando no.
            total = None
            if rc in (0, 100):
                total = len([l for l in out.splitlines() if l.strip() and not l.startswith((" ", "Obsoleting"))])
            rc2, out2 = run([mgr, "-q", "--cacheonly", "updateinfo", "list", "--security"], timeout=90)
            sec = len([l for l in out2.splitlines() if l.strip()]) if rc2 == 0 else None
            return {"manager": mgr, "total": total, "security": sec}
    if which("zypper"):
        rc, out = run(["zypper", "-q", "--no-refresh", "lu"], timeout=90)
        total = len([l for l in out.splitlines() if l.startswith("v ")]) if rc == 0 else None
        return {"manager": "zypper", "total": total, "security": None}
    return {"manager": None, "total": None, "security": None}


def reboot_required() -> bool | None:
    if os.path.exists("/var/run/reboot-required"):
        return True
    if which("needs-restarting"):
        rc, _ = run(["needs-restarting", "-r"], timeout=60)
        if rc in (0, 1):
            return rc == 1
    if os.path.isdir("/var/lib/update-notifier") or which("apt-get"):
        return False
    return None


def inventory() -> dict:
    up = system.uptime()
    rc, fqdn = run(["hostname", "-f"], timeout=5)
    dmi = {k: (read("/sys/class/dmi/id/" + k) or "").strip() for k in ("sys_vendor", "product_name")}
    return {
        "hostname": socket.gethostname(),
        "fqdn": fqdn.strip() if rc == 0 else "",
        "os": os_release(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "virt": virtualization(),
        "vendor": dmi["sys_vendor"],
        "product": dmi["product_name"],
        "cpu_model": cpu_model(),
        "cpus": os.cpu_count() or 1,
        "mem_total": system.meminfo().get("MemTotal"),
        "boot_time": int(time.time() - up) if up else None,
        "ips": addresses(),
        "panel": panel(),
        "docker": bool(which("docker")) and os.path.exists("/var/run/docker.sock"),
        "updates": pending_updates(),
        "reboot_required": reboot_required(),
        "agent": {"version": VERSION, "python": platform.python_version(), "executable": sys.executable},
    }


def machine_id() -> str:
    return ((read("/etc/machine-id") or read("/var/lib/dbus/machine-id") or "").strip())
