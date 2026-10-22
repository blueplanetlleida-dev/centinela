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


class MigracionTest(unittest.TestCase):
    def test_base_de_datos_0_1(self):
        """Una base creada por la 0.1 (usuarios sin correo) se pone al dia sin perder nada."""
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v1.db")
            c = sqlite3.connect(path)
            c.executescript("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,"
                            " pw_hash TEXT NOT NULL, totp_secret TEXT, totp_last_step INTEGER NOT NULL DEFAULT 0,"
                            " created_at INTEGER NOT NULL);"
                            "INSERT INTO users (username, pw_hash, created_at) VALUES ('admin', 'x', 1);")
            c.commit()
            c.close()
            db._local.__dict__.clear()
            try:
                db.init(path)
                u = db.conn().execute("SELECT username, email, notify, weekly FROM users").fetchone()
                self.assertEqual(tuple(u), ("admin", None, 1, 1))
                self.assertEqual(db.meta_get("schema"), str(db.SCHEMA_VERSION))
            finally:
                db._local.__dict__.clear()


class AvisosTest(unittest.TestCase):
    def setUp(self):
        from centinela_central import mailer, settings
        self.mailer, self.settings = mailer, settings
        self.tmp = tempfile.TemporaryDirectory()
        db._local.__dict__.clear()
        db.init(os.path.join(self.tmp.name, "t.db"))
        self.enviados = []
        self._send = mailer.send
        mailer.send = lambda cfg, to, subject, html, text: self.enviados.append((to, subject, html, text))
        mailer._fallo["at"] = 0
        self.cfg = type("C", (), {"public_url": "https://central.test/flota", "smtp": {}})()
        settings.put("mail", dict(settings.MAIL_DEFAULT, host="smtp.test"))
        with db.tx() as c:
            c.execute("INSERT INTO users (username, pw_hash, created_at, email) VALUES ('ana', 'x', 1, 'ana@ejemplo.com')")
            c.execute("INSERT INTO users (username, pw_hash, created_at, email, notify) VALUES ('luis', 'x', 1, 'luis@ejemplo.com', 0)")

    def tearDown(self):
        self.mailer.send = self._send
        db._local.__dict__.clear()
        self.tmp.cleanup()

    def host_con_disco(self, pct, now):
        code = views.create_code("", 3600, "t", "l")   # sin etiqueta: el nombre sera el hostname
        r = views.enroll_agent({"code": code, "machine_id": "m%d" % pct, "hostname": "web%d" % pct}, "ip", now)
        host = auth.host_by_token(r["token"])
        ingest.ingest(host, {"reports": [{"ts": now, "metrics": {"fs": [fs("/", pct)]}}]}, now, "ip")

    def test_avisa_tras_el_retraso_y_solo_a_quien_quiere(self):
        now = int(time.time())
        self.settings.put("notify", dict(self.settings.NOTIFY_DEFAULT, delay=300, extra_to=["guardia@ejemplo.com"]))
        self.host_con_disco(97, now)
        self.mailer.notify_alerts(self.cfg, now + 60)       # aun no ha pasado el retraso
        self.assertEqual(self.enviados, [])
        self.mailer.notify_alerts(self.cfg, now + 400)
        self.assertEqual(len(self.enviados), 1)
        to, subject, html, text = self.enviados[0]
        self.assertEqual(to, ["ana@ejemplo.com", "guardia@ejemplo.com"])
        self.assertIn("CRÍTICO", subject)
        self.assertIn("Disco / al 97 %", html)
        self.assertIn("https://central.test/flota/host/", html)
        self.mailer.notify_alerts(self.cfg, now + 500)       # no se repite
        self.assertEqual(len(self.enviados), 1)

    def test_solo_criticos(self):
        now = int(time.time())
        self.settings.put("notify", dict(self.settings.NOTIFY_DEFAULT, delay=0, min_sev="crit"))
        self.host_con_disco(91, now)                         # aviso, no critico
        self.mailer.notify_alerts(self.cfg, now + 1)
        self.assertEqual(self.enviados, [])

    def test_sin_correo_configurado_no_acumula(self):
        now = int(time.time())
        self.settings.put("mail", dict(self.settings.MAIL_DEFAULT))
        self.settings.put("notify", dict(self.settings.NOTIFY_DEFAULT, delay=0))
        self.host_con_disco(97, now)
        self.mailer.notify_alerts(self.cfg, now + 1)
        pend = db.conn().execute("SELECT COUNT(*) FROM alerts WHERE notified = 0").fetchone()[0]
        self.assertEqual(pend, 0)                            # el dia que se configure no llega una avalancha
        self.assertEqual(self.enviados, [])

    def test_informe_semanal(self):
        now = int(time.time())
        self.host_con_disco(50, now)
        self.mailer.send_weekly(self.cfg, now)
        to, subject, html, text = self.enviados[0]
        self.assertIn("Informe semanal", subject)
        # luis no quiere avisos, pero el informe semanal si (son opciones separadas).
        self.assertEqual(to, ["ana@ejemplo.com", "luis@ejemplo.com"])
        self.assertIn("web50", html)
        self.assertIn("web50", text)

    def test_formulario_valida(self):
        class F(dict):
            def get(self, k, d=None):
                return dict.get(self, k, d)
        base = {"method": "smtp", "host": "smtp.ejemplo.com", "port": "587", "security": "starttls",
                "from": "centinela@ejemplo.com", "delay": "5", "weekly_day": "1", "weekly_hour": "8",
                "timezone": "Europe/Madrid", "enabled": "1"}
        m, n = views.parse_notify_form(F(base))
        self.assertEqual((m["host"], n["delay"], n["enabled"]), ("smtp.ejemplo.com", 300, True))
        for malo in ({"host": "smtp ejemplo"}, {"from": "no-es-correo"}, {"timezone": "../../etc/passwd"},
                     {"extra_to": "ana@ejemplo.com, x"}, {"port": "99999"}):
            with self.assertRaises(views.FormError, msg=str(malo)):
                views.parse_notify_form(F(dict(base, **malo)))
