"""Temperaturas y ventiladores: hwmon y zonas termicas del nucleo, e IPMI si hay BMC.

En una maquina virtual no suele haber ningun sensor; se devuelve una lista
vacia y el central lo muestra como «no disponible», nunca como cero.
"""

from __future__ import annotations

import glob
import os

from ..util import read, read_int, run, which

CPU_CHIPS = {"coretemp", "k10temp", "zenpower", "cpu_thermal", "x86_pkg_temp", "soc_thermal"}
DISK_CHIPS = {"nvme", "drivetemp"}


def _limite(path: str):
    """Umbral del sensor en grados, descartando los valores absurdos que dan algunos chips."""
    v = read_int(path)
    if v is None:
        return None
    c = v / 1000.0
    return round(c, 1) if 20 < c < 150 else None


def _kind(chip: str) -> str:
    if chip in CPU_CHIPS:
        return "cpu"
    if chip in DISK_CHIPS:
        return "disk"
    return "other"


def hwmon() -> dict:
    temps, fans = [], []
    for hw in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
        chip = (read(hw + "/name") or read(hw + "/device/name") or os.path.basename(hw)).strip()
        # Para discos interesa saber cual: nvme0, sda...
        disp = os.path.basename(os.path.realpath(hw + "/device")) if os.path.exists(hw + "/device") else ""
        for inp in sorted(glob.glob(hw + "/temp*_input")):
            base = inp[: -len("input")]
            v = read_int(inp)
            if v is None:
                continue
            c = v / 1000.0
            if c <= -40 or c >= 150:
                continue  # sensor desconectado o lectura basura
            label = (read(base + "label") or "").strip() or os.path.basename(base).rstrip("_")
            if _kind(chip) == "disk" and disp:
                label = "%s %s" % (disp, label)
            temps.append({
                "chip": chip, "label": label, "kind": _kind(chip), "c": round(c, 1),
                "high": _limite(base + "max"), "crit": _limite(base + "crit"),
            })
        for inp in sorted(glob.glob(hw + "/fan*_input")):
            rpm = read_int(inp)
            if rpm is None:
                continue
            base = inp[: -len("input")]
            label = (read(base + "label") or "").strip() or os.path.basename(base).rstrip("_")
            fans.append({"chip": chip, "label": label, "rpm": rpm})

    # Sin hwmon (algunos ARM y portatiles viejos), las zonas termicas del nucleo.
    if not temps:
        for tz in sorted(glob.glob("/sys/class/thermal/thermal_zone*")):
            v = read_int(tz + "/temp")
            if v is None or not (-40 < v / 1000.0 < 150):
                continue
            tipo = (read(tz + "/type") or os.path.basename(tz)).strip()
            temps.append({
                "chip": "thermal", "label": tipo, "kind": "cpu" if "cpu" in tipo or "x86" in tipo else "other",
                "c": round(v / 1000.0, 1), "high": None, "crit": None,
            })
    return {"temps": temps, "fans": fans}


def _ipmi_dev() -> bool:
    return any(os.path.exists(p) for p in ("/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0"))


def ipmi_available() -> bool:
    return bool(which("ipmitool")) and _ipmi_dev()


def parse_ipmi_sdr(out: str) -> list:
    """Lineas de «ipmitool -c sdr type X»: nombre,valor,unidad,estado[,...]."""
    rows = []
    for line in out.splitlines():
        f = [x.strip() for x in line.split(",")]
        if len(f) < 4:
            continue
        name, val, unit, status = f[0], f[1], f[2], f[3]
        try:
            num = float(val)
        except ValueError:
            num = None
        rows.append({"name": name, "value": num, "unit": unit, "status": status})
    return rows


def ipmi() -> dict:
    """Sensores del BMC. Lento (varios segundos), por eso va en una seccion aparte."""
    out = {"temps": [], "fans": [], "psu": []}
    for tipo, clave in (("Temperature", "temps"), ("Fan", "fans"), ("Power Supply", "psu")):
        rc, txt = run(["ipmitool", "-c", "sdr", "type", tipo], timeout=30)
        if rc != 0:
            continue
        for r in parse_ipmi_sdr(txt):
            if r["status"] in ("ns", ""):  # sin lectura: ranura vacia
                continue
            out[clave].append(r)
    return out
