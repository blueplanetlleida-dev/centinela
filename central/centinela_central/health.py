"""Reglas de salud: del ultimo estado de un servidor, la lista de problemas.

Cada problema tiene una clave estable (p. ej. «fs:/var») para que la alerta
se abra una vez, se actualice mientras dure y se cierre sola al resolverse.
"""

from __future__ import annotations

from .fmt import bytes_h, duration_h

CRIT, WARN, INFO = "crit", "warn", "info"
RANK = {"ok": 0, "new": 0, INFO: 1, WARN: 2, CRIT: 3, "offline": 4}

# Una seccion que deja de llegar (se desinstalo smartctl, se desmonto el RAID)
# no debe dejar un problema abierto para siempre.
SECTION_MAX_AGE = 24 * 3600

# Umbrales por defecto cuando el sensor no trae los suyos: (aviso, critico) en °C.
TEMP_DEFAULTS = {"cpu": (85, 95), "disk": (60, 70), "other": (85, 100)}
SMART_TEMP = {"nvme": (70, 80), "hdd": (55, 65)}


def _p(key, sev, title, detail=""):
    return {"key": key, "sev": sev, "title": title, "detail": detail}


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def section(state: dict, name: str, now: int):
    s = (state.get("sections") or {}).get(name)
    if not isinstance(s, dict) or now - int(s.get("ts") or 0) > SECTION_MAX_AGE:
        return None
    return s.get("data")


def evaluate(state: dict, now: int, skew: int | None = None) -> list:
    out = []
    m = state.get("metrics") or {}
    inv = section(state, "inventory", now) or {}

    for f in m.get("fs") or []:
        if not isinstance(f, dict):
            continue
        mnt = str(f.get("mount", "?"))
        if f.get("unreachable"):
            out.append(_p("fs:" + mnt, WARN, "El montaje %s no responde" % mnt,
                          "%s (%s) no contesta: ¿se ha caído el servidor remoto?" % (f.get("dev", ""), f.get("fs", ""))))
            continue
        pct = _num(f.get("pct"))
        if pct is not None and pct >= 90:
            out.append(_p("fs:" + mnt, CRIT if pct >= 95 else WARN, "Disco %s al %s %%" % (mnt, _fmt(pct)),
                          "Quedan %s libres de %s" % (bytes_h(f.get("avail")), bytes_h(f.get("total")))))
        ino = _num(f.get("inodes_pct"))
        if ino is not None and ino >= 90:
            out.append(_p("inodes:" + mnt, CRIT if ino >= 95 else WARN, "Inodos de %s al %s %%" % (mnt, _fmt(ino)),
                          "Con los inodos agotados no se pueden crear ficheros aunque quede espacio: "
                          "suele ser una carpeta de sesiones, caché o correo que no se limpia."))
        if mnt == "/" and f.get("ro"):
            out.append(_p("fs:/:ro", CRIT, "La raíz está montada en solo lectura",
                          "El núcleo la remonta así cuando detecta errores en el sistema de ficheros. Revisa dmesg."))

    mem = m.get("mem") or {}
    pct = _num(mem.get("pct"))
    if pct is not None and pct >= 90:
        out.append(_p("mem", CRIT if pct >= 95 else WARN, "Memoria al %s %%" % _fmt(pct),
                      "Disponibles %s de %s" % (bytes_h(mem.get("available")), bytes_h(mem.get("total")))))
    swap = m.get("swap") or {}
    spct = _num(swap.get("pct"))
    if spct is not None and spct >= 80 and (swap.get("total") or 0) >= 256 * 1024 * 1024:
        out.append(_p("swap", WARN, "Swap al %s %%" % _fmt(spct),
                      "Usados %s de %s: la memoria se queda corta y el sistema va a disco." %
                      (bytes_h(swap.get("used")), bytes_h(swap.get("total")))))

    cpu = m.get("cpu") or {}
    cores = _num(cpu.get("count")) or _num(inv.get("cpus")) or 1
    load = m.get("load") or []
    if len(load) >= 3 and _num(load[2]) is not None:
        per = load[2] / cores
        if per >= 2:
            out.append(_p("load", CRIT if per >= 4 else WARN, "Carga sostenida de %s con %d núcleos" % (_fmt(load[2], 2), cores),
                          "Media de 15 minutos: hay más trabajo del que la máquina puede atender."))
    steal = _num(cpu.get("steal"))
    if steal is not None and steal >= 25:
        out.append(_p("steal", WARN, "El anfitrión retiene CPU (%s %% steal)" % _fmt(steal),
                      "La máquina virtual espera CPU que el proveedor no le da: el servidor físico está saturado."))

    for t in m.get("temps") or []:
        c = _num((t or {}).get("c"))
        if c is None:
            continue
        kind = t.get("kind") if t.get("kind") in TEMP_DEFAULTS else "other"
        hi = _num(t.get("high")) or TEMP_DEFAULTS[kind][0]
        cr = _num(t.get("crit")) or TEMP_DEFAULTS[kind][1]
        if c >= min(hi, cr):
            nombre = "%s %s" % (t.get("chip", ""), t.get("label", ""))
            out.append(_p("temp:" + nombre.strip(), CRIT if c >= cr else WARN,
                          "Temperatura %s: %s °C" % (nombre.strip(), _fmt(c)),
                          "Umbral de aviso %s °C, crítico %s °C." % (_fmt(hi), _fmt(cr))))

    svc = section(state, "services", now) or {}
    failed = [u.get("unit", "?") for u in (svc.get("failed") or []) if isinstance(u, dict)]
    if failed:
        out.append(_p("units", WARN, "%d servicio(s) caído(s)" % len(failed),
                      ", ".join(failed[:6]) + (" y %d más" % (len(failed) - 6) if len(failed) > 6 else "")))

    ts = section(state, "timesync", now) or {}
    if ts.get("ntp_enabled") is False:
        out.append(_p("time", WARN, "La hora no se sincroniza por NTP",
                      "Un reloj desviado rompe TLS, el doble factor y el orden de los logs."))
    elif ts.get("synced") is False:
        out.append(_p("time", WARN, "La hora no está sincronizada", "NTP está activado pero aún no ha sincronizado."))
    if skew is not None and abs(skew) > 120:
        out.append(_p("skew", WARN, "Reloj desviado %s respecto al central" % duration_h(abs(skew)),
                      "El agente fecha sus informes con su reloj: las gráficas saldrán desplazadas."))

    for a in section(state, "raid", now) or []:
        if not isinstance(a, dict):
            continue
        name = a.get("name", "?")
        if a.get("degraded"):
            out.append(_p("raid:" + name, CRIT, "RAID %s degradado" % name,
                          "Estado de los discos [%s]%s. Un fallo más y se pierden datos." %
                          (a.get("disks", ""), (", han fallado " + ", ".join(a["failed"])) if a.get("failed") else "")))
        sync = a.get("sync") or {}
        if sync:
            out.append(_p("raid-sync:" + name, INFO, "RAID %s: %s al %s %%" % (name, sync.get("op"), _fmt(sync.get("pct"))),
                          "Mientras dura, el rendimiento de disco baja."))

    for z in section(state, "zfs", now) or []:
        if not isinstance(z, dict):
            continue
        name, health = z.get("name", "?"), str(z.get("health", ""))
        if health and health != "ONLINE":
            out.append(_p("zfs:" + name, WARN if health == "DEGRADED" else CRIT,
                          "Pool ZFS %s: %s" % (name, health), "zpool status -x %s" % name))
        zp = _num(z.get("pct"))
        if zp is not None and zp >= 85:
            out.append(_p("zfs-cap:" + name, CRIT if zp >= 95 else WARN, "Pool ZFS %s al %s %%" % (name, _fmt(zp)),
                          "ZFS se vuelve muy lento por encima del 85-90 %."))

    for d in section(state, "smart", now) or []:
        out.extend(_smart(d))

    ipmi = section(state, "ipmi", now) or {}
    for grupo, nombre in (("temps", "Sensor"), ("fans", "Ventilador"), ("psu", "Fuente")):
        for r in ipmi.get(grupo) or []:
            st = str((r or {}).get("status", "")).lower()
            if st in ("ok", "ns", ""):
                continue
            sev = CRIT if st in ("cr", "nr") else WARN
            val = r.get("value")
            out.append(_p("ipmi:" + str(r.get("name")), sev, "%s %s: %s" % (nombre, r.get("name"), st.upper()),
                          ("Lectura %s %s" % (_fmt(val), r.get("unit", ""))) if val is not None else ""))

    upd = inv.get("updates") or {}
    if (_num(upd.get("security")) or 0) > 0:
        out.append(_p("updates", WARN, "%d actualización(es) de seguridad pendiente(s)" % upd["security"],
                      "%s en total, según %s." % (upd.get("total"), upd.get("manager"))))
    if inv.get("reboot_required"):
        out.append(_p("reboot", INFO, "Reinicio pendiente", "Hay un núcleo o librerías actualizados que no se usarán hasta reiniciar."))

    err = state.get("errors") or {}
    if err.get("data"):
        out.append(_p("agent-errors", INFO, "El agente no pudo leer: " + ", ".join(sorted(err["data"])),
                      "; ".join("%s: %s" % (k, v) for k, v in sorted(err["data"].items()))[:400]))
    return out


def _smart(d) -> list:
    if not isinstance(d, dict) or d.get("standby"):
        return []
    dev = str(d.get("dev", "?"))
    model = d.get("model") or ""
    out = []
    if d.get("passed") is False:
        out.append(_p("smart:" + dev, CRIT, "El disco %s anuncia fallo (SMART)" % dev,
                      "%s. Haz copia de lo que tenga y cámbialo." % model))
    malos = [(k, _num(d.get(k))) for k in ("reallocated", "pending", "uncorrectable")]
    malos = [(k, v) for k, v in malos if v]
    if malos:
        nombres = {"reallocated": "reasignados", "pending": "pendientes", "uncorrectable": "incorregibles"}
        out.append(_p("smart-sect:" + dev, WARN, "El disco %s tiene sectores dañados" % dev,
                      "%s: %s. Suele ir a más." % (model, ", ".join("%d %s" % (v, nombres[k]) for k, v in malos))))
    cw = _num(d.get("critical_warning"))
    if cw:
        out.append(_p("nvme-warn:" + dev, CRIT, "El NVMe %s activa un aviso crítico" % dev, "%s (critical_warning=%d)" % (model, cw)))
    wear = _num(d.get("wear_pct"))
    if wear is not None and wear >= 90:
        out.append(_p("wear:" + dev, CRIT if wear >= 100 else WARN, "El SSD %s ha consumido el %d %% de su vida" % (dev, wear), model))
    spare, thr = _num(d.get("spare_pct")), _num(d.get("spare_threshold"))
    if spare is not None and thr is not None and spare <= thr:
        out.append(_p("spare:" + dev, CRIT, "El SSD %s se ha quedado sin reserva" % dev, "%s: %d %% (umbral %d %%)" % (model, spare, thr)))
    if _num(d.get("media_errors")):
        out.append(_p("media:" + dev, WARN, "El NVMe %s registra errores de medio" % dev, "%s: %d" % (model, d["media_errors"])))
    t = _num(d.get("temp"))
    if t is not None:
        hi, cr = SMART_TEMP["nvme" if "nvme" in dev or d.get("type") == "nvme" else "hdd"]
        if t >= hi:
            out.append(_p("smart-temp:" + dev, CRIT if t >= cr else WARN, "Disco %s a %d °C" % (dev, t), model))
    return out


def worst(problems: list) -> str:
    best = "ok"
    for p in problems:
        if RANK.get(p["sev"], 0) > RANK[best]:
            best = p["sev"]
    return best


def _fmt(v, nd: int = 1) -> str:
    if v is None:
        return "?"
    s = ("%." + str(nd) + "f") % v
    s = s.rstrip("0").rstrip(".") if "." in s else s
    return s.replace(".", ",")
