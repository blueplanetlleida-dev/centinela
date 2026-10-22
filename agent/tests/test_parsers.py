"""Pruebas de los analizadores que dependen de hardware que no siempre hay a mano.

python3 -m unittest discover -s agent/tests
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from centinela_agent.collect import sensors, storage, system  # noqa: E402

MDSTAT = """Personalities : [raid1] [raid6] [raid5] [raid4]
md1 : active raid1 sdb2[1] sda2[0](F)
      976630336 blocks super 1.2 [2/1] [_U]
      bitmap: 3/8 pages [12KB], 65536KB chunk

md0 : active raid5 sdd1[3] sdc1[1] sde1[0]
      1953260544 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/3] [UUU]
      [===>.................]  resync = 17.3% (169124864/976630272) finish=93.4min speed=144032K/sec

md2 : active (auto-read-only) raid1 sdf1[0] sdg1[1]
      1046528 blocks super 1.2 [2/2] [UU]

unused devices: <none>
"""

IPMI = """Inlet Temp,23,degrees C,ok,7.1,Inlet Ambient
Exhaust Temp,41,degrees C,ok,7.1,
Temp,no reading,,ns,3.1,
CPU2 Temp,92,degrees C,cr,3.2,
"""


class MdstatTest(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(storage, "read", return_value=MDSTAT):
            self.arrays = {a["name"]: a for a in storage.mdstat()}

    def test_degradado_por_disco_fallido(self):
        md1 = self.arrays["md1"]
        self.assertTrue(md1["degraded"])
        self.assertEqual(md1["failed"], ["sda2"])
        self.assertEqual(md1["disks"], "_U")

    def test_resync_no_es_degradado(self):
        md0 = self.arrays["md0"]
        self.assertFalse(md0["degraded"])
        self.assertEqual(md0["level"], "raid5")
        self.assertEqual(md0["sync"], {"op": "resync", "pct": 17.3})

    def test_solo_lectura(self):
        md2 = self.arrays["md2"]
        self.assertEqual(md2["level"], "raid1")
        self.assertFalse(md2["degraded"])


class IpmiTest(unittest.TestCase):
    def test_lecturas(self):
        rows = sensors.parse_ipmi_sdr(IPMI)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0], {"name": "Inlet Temp", "value": 23.0, "unit": "degrees C", "status": "ok"})
        self.assertIsNone(rows[2]["value"])
        self.assertEqual(rows[3]["status"], "cr")


class CpuTest(unittest.TestCase):
    def test_porcentajes(self):
        prev = [100, 0, 50, 800, 20, 0, 0, 30, 0, 0]
        cur = [200, 0, 100, 1600, 40, 0, 0, 60, 0, 0]
        c = system.cpu_percent(prev, cur)
        # total 1000: idle 800 + iowait 20 -> 18 % de uso; steal 30 -> 3 %
        self.assertEqual(c["pct"], 18.0)
        self.assertEqual(c["iowait"], 2.0)
        self.assertEqual(c["steal"], 3.0)

    def test_sin_lectura_previa(self):
        self.assertIsNone(system.cpu_percent(None, [1] * 10))



class UpdaterTest(unittest.TestCase):
    def test_versiones(self):
        from centinela_agent.updater import vnum
        self.assertTrue(vnum("0.10.0") > vnum("0.9.9"))
        self.assertEqual(vnum("1.2"), (1, 2, 0))

    def test_paquete_con_rutas_peligrosas(self):
        import io
        import tarfile
        import tempfile
        from centinela_agent.updater import _safe_extract
        for nombre in ("../fuera.txt", "/etc/passwd", "otro/fichero.py"):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as t:
                info = tarfile.TarInfo(nombre)
                info.size = 2
                t.addfile(info, io.BytesIO(b"hi"))
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    _safe_extract(buf.getvalue(), d)

    def test_no_baja_de_version(self):
        from centinela_agent import updater
        u = updater.Updater(transport=None)
        llamado = []
        u._apply = lambda *a: llamado.append(a)
        u.check({"version": "0.0.1", "sha256": "a" * 64})
        u.check({"version": "9.0.0", "sha256": "malo"})
        u.check({"version": "9.0.0", "sha256": "a" * 64, "path": "/../../etc"})
        self.assertEqual(llamado, [])


if __name__ == "__main__":
    unittest.main()
