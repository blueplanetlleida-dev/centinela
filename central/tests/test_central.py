"""Pruebas del central: reglas, alertas, ingesta y API.

Con el entorno del central: python -m unittest discover -s central/tests
"""

import gzip
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from centinela_central import auth, db, health, ingest, views  # noqa: E402


def fs(mount, pct):
    return {"mount": mount, "dev": "/dev/x", "fs": "ext4", "total": 100, "used": pct, "avail": 100 - pct,
            "pct": float(pct), "inodes_pct": 1.0, "ro": False}


class HealthTest(unittest.TestCase):
    def keys(self, state, skew=None):
        return {p["key"]: p["sev"] for p in health.evaluate(state, int(time.time()), skew)}

    def test_disco(self):
        k = self.keys({"metrics": {"fs": [fs("/", 91), fs("/var", 96), fs("/home", 50)]}})
        self.assertEqual(k, {"fs:/": "warn", "fs:/var": "crit"})

    def test_temperatura_con_umbral_del_sensor(self):
        t = {"chip": "coretemp", "label": "Package id 0", "kind": "cpu", "c": 81.0, "high": 80.0, "crit": 100.0}
        self.assertEqual(self.keys({"metrics": {"temps": [t]}}), {"temp:coretemp Package id 0": "warn"})

    def test_temperatura_sin_umbral_usa_el_de_disco(self):
        t = {"chip": "nvme", "label": "nvme0 Composite", "kind": "disk", "c": 71.0, "high": None, "crit": None}
        self.assertEqual(self.keys({"metrics": {"temps": [t]}}), {"temp:nvme nvme0 Composite": "crit"})

    def test_seccion_caducada_no_cuenta(self):
        viejo = int(time.time()) - 2 * 86400
        st = {"sections": {"raid": {"ts": viejo, "data": [{"name": "md0", "degraded": True, "disks": "U_"}]}}}
        self.assertEqual(self.keys(st), {})

    def test_desfase_de_reloj(self):
        self.assertEqual(self.keys({}, skew=-400), {"skew": "warn"})
        self.assertEqual(self.keys({}, skew=30), {})


class TotpTest(unittest.TestCase):
    def test_rfc6238(self):
        # Vector de la RFC 6238 (SHA1, T=59 s), recortado a 6 cifras.
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(auth._hotp(secret, 1), "287082")
        self.assertEqual(auth.totp_check(secret, "287082", 0, now=59), 1)
        self.assertIsNone(auth.totp_check(secret, "287082", 1, now=59))  # no se puede reutilizar

    def test_contrasena(self):
        h = auth.hash_password("una contraseña larga")
        self.assertTrue(auth.verify_password("una contraseña larga", h))
        self.assertFalse(auth.verify_password("otra", h))


class FlujoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db._local.__dict__.clear()
        db.init(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        db._local.__dict__.clear()
        self.tmp.cleanup()

    def alta(self, mid="m1"):
        code = views.create_code("prueba", 3600, "test", "local")
        return views.enroll_agent({"code": code, "machine_id": mid, "hostname": "h1"}, "127.0.0.1", int(time.time()))

    def test_codigo_de_un_solo_uso(self):
        code = views.create_code("x", 3600, "test", "local")
        now = int(time.time())
        self.assertIn("token", views.enroll_agent({"code": code.lower(), "machine_id": "a"}, "ip", now))
        self.assertIn("error", views.enroll_agent({"code": code, "machine_id": "b"}, "ip", now))

    def test_reinstalar_conserva_el_servidor(self):
        a = self.alta("misma")
        b = self.alta("misma")
        self.assertEqual(a["agent_id"], b["agent_id"])
        self.assertTrue(b["replaced"])
        self.assertIsNone(auth.host_by_token(a["token"]))
        self.assertIsNotNone(auth.host_by_token(b["token"]))

    def test_alerta_se_abre_y_se_cierra(self):
        r = self.alta()
        host = auth.host_by_token(r["token"])
        now = int(time.time())
        ingest.ingest(host, {"reports": [{"ts": now, "metrics": {"fs": [fs("/", 97)]}}]}, now, "ip")
        abiertas = db.conn().execute("SELECT key, sev FROM alerts WHERE closed_at IS NULL").fetchall()
        self.assertEqual([(a["key"], a["sev"]) for a in abiertas], [("fs:/", "crit")])
        self.assertEqual(db.conn().execute("SELECT status FROM hosts").fetchone()[0], "crit")

        host = auth.host_by_token(r["token"])
        ingest.ingest(host, {"reports": [{"ts": now + 60, "metrics": {"fs": [fs("/", 40)]}}]}, now + 60, "ip")
        self.assertEqual(db.conn().execute("SELECT COUNT(*) FROM alerts WHERE closed_at IS NULL").fetchone()[0], 0)
        self.assertEqual(db.conn().execute("SELECT status FROM hosts").fetchone()[0], "ok")

    def test_informes_fuera_de_rango_se_descartan(self):
        r = self.alta()
        host = auth.host_by_token(r["token"])
        now = int(time.time())
        with self.assertRaises(ingest.IngestError):
            ingest.ingest(host, {"reports": [{"ts": now - 30 * 86400, "metrics": {}}]}, now, "ip")


class ApiTest(unittest.TestCase):
    """La API de verdad, con el cliente de pruebas de Starlette."""

    @classmethod
    def setUpClass(cls):
        try:
            from starlette.testclient import TestClient
        except ImportError:
            raise unittest.SkipTest("sin starlette.testclient (falta httpx)")
        from centinela_central.config import Config
        from centinela_central.web import create_app
        cls.tmp = tempfile.TemporaryDirectory()
        conf = os.path.join(cls.tmp.name, "c.conf")
        with open(conf, "w") as f:
            f.write("[server]\npublic_url = http://testserver\ndb = %s\n" % os.path.join(cls.tmp.name, "a.db"))
        db._local.__dict__.clear()
        cls.client = TestClient(create_app(Config(conf)))

    @classmethod
    def tearDownClass(cls):
        db._local.__dict__.clear()
        cls.tmp.cleanup()

    def test_report_sin_token(self):
        r = self.client.post("/api/v1/report", content=b"{}")
        self.assertEqual(r.status_code, 401)

    def test_bomba_gzip(self):
        code = views.create_code("x", 3600, "t", "l")
        tok = views.enroll_agent({"code": code, "machine_id": "z"}, "ip", int(time.time()))["token"]
        bomba = gzip.compress(b"[" + b"0," * 40_000_000 + b"0]")
        r = self.client.post("/api/v1/report", content=bomba,
                             headers={"Authorization": "Bearer " + tok, "Content-Encoding": "gzip"})
        self.assertEqual(r.status_code, 413)

    def test_panel_pide_login(self):
        r = self.client.get("/", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertTrue(r.headers["location"].endswith("/login"))

    def test_csp(self):
        r = self.client.get("/login")
        self.assertIn("script-src 'self'", r.headers["content-security-policy"])

    def test_informe_valido(self):
        code = views.create_code("x", 3600, "t", "l")
        tok = views.enroll_agent({"code": code, "machine_id": "y"}, "ip", int(time.time()))["token"]
        body = gzip.compress(json.dumps({"reports": [{"ts": int(time.time()), "metrics": {"load": [0.1, 0.1, 0.1]}}]}).encode())
        r = self.client.post("/api/v1/report", content=body,
                             headers={"Authorization": "Bearer " + tok, "Content-Encoding": "gzip"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["accepted"], 1)


if __name__ == "__main__":
    unittest.main()
