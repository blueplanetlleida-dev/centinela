"""Recolectores y el muestreador que compone cada informe.

Cada informe lleva siempre las metricas rapidas (las que necesitan dos
lecturas para dar una tasa: CPU, E/S y red) y, cuando les toca, las
secciones lentas, cada una con su propio periodo. Un recolector que falla
deja su error en el informe y no tumba a los demas.
"""

from __future__ import annotations

import time

from ..util import log
from . import disks, inventory, net, sensors, services, storage, system

# seccion -> (periodo en segundos, ¿aplica en esta maquina?, funcion)
SECTIONS = {
    "inventory": (6 * 3600, lambda: True, inventory.inventory),
    "services": (60, services.systemd_available, services.services),
    "timesync": (900, lambda: True, services.timesync),
    "raid": (300, lambda: bool(storage.mdstat()), storage.mdstat),
    "zfs": (300, storage.zfs_available, storage.zpools),
    "smart": (1800, storage.smart_available, storage.smart),
    "ipmi": (300, sensors.ipmi_available, sensors.ipmi),
}


class Sampler:
    def __init__(self):
        self._prev = None  # (monotonic, cpu, diskstats, net)
        self._due = {name: 0.0 for name in SECTIONS}
        self._applies = {}

    def prime(self) -> None:
        """Primera lectura de contadores, para que el primer informe ya tenga tasas."""
        self._prev = (time.monotonic(), system.cpu_times(), disks.diskstats(), net.counters())

    def force_all(self) -> None:
        for name in self._due:
            self._due[name] = 0.0

    def metrics(self, errors: dict) -> dict:
        now = time.monotonic()
        cpu, dstats, ncount = system.cpu_times(), disks.diskstats(), net.counters()
        prev = self._prev
        self._prev = (now, cpu, dstats, ncount)
        dt = now - prev[0] if prev else 0.0

        m = {"load": system.load(), "uptime": system.uptime()}
        steps = (
            ("cpu", lambda: system.cpu_percent(prev[1] if prev else None, cpu)),
            ("memory", system.memory),
            ("procs", system.processes),
            ("fs", disks.filesystems),
            ("io", lambda: disks.io_rates(prev[2] if prev else None, dstats, dt)),
            ("net", lambda: net.rates(prev[3] if prev else None, ncount, dt)),
            ("sensors", sensors.hwmon),
        )
        for name, fn in steps:
            try:
                v = fn()
            except Exception as e:  # un recolector roto no debe parar el resto
                log.exception("fallo recogiendo %s", name)
                errors[name] = str(e)[:300]
                continue
            if name == "memory":
                m.update(v)
            elif name == "sensors":
                m["temps"], m["fans"] = v["temps"], v["fans"]
            else:
                m[name] = v
        return m

    def sections(self, errors: dict) -> dict:
        out = {}
        now = time.monotonic()
        for name, (period, applies, fn) in SECTIONS.items():
            if now < self._due[name]:
                continue
            self._due[name] = now + period
            try:
                # Si algo no existe en esta maquina (ZFS, IPMI...) se comprueba
                # de nuevo cada periodo por si se instala, pero no se envia nada.
                if not applies():
                    continue
                out[name] = fn()
            except Exception as e:
                log.exception("fallo recogiendo %s", name)
                errors[name] = str(e)[:300]
        return out
