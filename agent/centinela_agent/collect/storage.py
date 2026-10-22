"""Salud de los discos: SMART (SATA, SAS y NVMe), RAID por software y ZFS."""

from __future__ import annotations

import re

from ..util import read, run, run_json, which

# Atributos SATA que anticipan un fallo: sectores reasignados, pendientes e incorregibles.
ATA_ATTRS = {5: "reallocated", 197: "pending", 198: "uncorrectable", 199: "crc_errors"}


def smart_available() -> bool:
    return bool(which("smartctl"))


def _smart_disk(name: str, dtype: str) -> dict | None:
    # -n standby: no despertar un disco dormido solo para leerle la temperatura.
    rc, j = run_json(["smartctl", "-a", "-j", "-n", "standby", "-d", dtype, name], timeout=60)
    if not isinstance(j, dict):
        return None
    if rc & 2 and "standby" in str(j.get("smartctl", {}).get("messages", "")).lower():
        return {"dev": name, "standby": True}
    sup = j.get("smart_support") or {}
    if sup and not sup.get("available", True):
        return None  # discos virtuales: no tienen SMART que leer
    d = {
        "dev": name,
        "type": dtype,
        "model": j.get("model_name") or j.get("scsi_model_name") or "",
        "serial": j.get("serial_number") or "",
        "capacity": (j.get("user_capacity") or {}).get("bytes"),
        "passed": (j.get("smart_status") or {}).get("passed"),
        "temp": (j.get("temperature") or {}).get("current"),
        "power_on_hours": (j.get("power_on_time") or {}).get("hours"),
    }
    for a in (j.get("ata_smart_attributes") or {}).get("table", []) or []:
        key = ATA_ATTRS.get(a.get("id"))
        if key:
            d[key] = (a.get("raw") or {}).get("value")
    nv = j.get("nvme_smart_health_information_log")
    if isinstance(nv, dict):
        d["wear_pct"] = nv.get("percentage_used")
        d["media_errors"] = nv.get("media_errors")
        d["critical_warning"] = nv.get("critical_warning")
        d["spare_pct"] = nv.get("available_spare")
        d["spare_threshold"] = nv.get("available_spare_threshold")
    if d["passed"] is None and d["temp"] is None and len([k for k in d if d[k] not in (None, "")]) <= 3:
        return None
    return d


def smart() -> list:
    _, scan = run_json(["smartctl", "--scan-open", "-j"], timeout=30)
    out = []
    for dev in (scan or {}).get("devices", []) or []:
        name, dtype = dev.get("name"), dev.get("type") or "auto"
        if not name:
            continue
        d = _smart_disk(name, dtype)
        if d:
            out.append(d)
    return out


_MD = re.compile(r"^(md\S+)\s*:\s*(\S+)\s+(?:\((?:auto-)?read-only\)\s+)?(raid\d+|linear|multipath)?\s*(.*)$")


def mdstat() -> list:
    raw = read("/proc/mdstat") or ""
    arrays, cur = [], None
    for line in raw.splitlines():
        m = _MD.match(line)
        if m:
            members = m.group(4).split()
            cur = {
                "name": m.group(1), "state": m.group(2), "level": m.group(3) or "",
                "members": [re.sub(r"\[\d+\]", "", x) for x in members],
                "failed": [re.sub(r"\[\d+\](\(F\))?", "", x) for x in members if "(F)" in x],
                "disks": "", "degraded": False, "sync": None,
            }
            arrays.append(cur)
            continue
        if cur is None:
            continue
        s = re.search(r"\[(\d+)/(\d+)\]\s+\[([U_]+)\]", line)
        if s:
            cur["disks"] = s.group(3)
            cur["degraded"] = "_" in s.group(3) or int(s.group(2)) < int(s.group(1))
        p = re.search(r"(resync|recovery|reshape|check)\s*=\s*([\d.]+)%", line)
        if p:
            cur["sync"] = {"op": p.group(1), "pct": float(p.group(2))}
    for a in arrays:
        if a["failed"]:
            a["degraded"] = True
    return arrays


def zfs_available() -> bool:
    return bool(which("zpool"))


def zpools() -> list:
    rc, out = run(["zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,cap,health"], timeout=30)
    if rc != 0:
        return []
    pools = []
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 6:
            continue
        try:
            pools.append({
                "name": f[0], "size": int(f[1]), "alloc": int(f[2]), "free": int(f[3]),
                "pct": float(f[4].rstrip("%")), "health": f[5],
            })
        except ValueError:
            continue
    return pools
