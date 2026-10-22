"""Configuracion del central (/etc/centinela-central/central.conf)."""

from __future__ import annotations

import configparser
import os
from pathlib import Path

DEFAULT_FILE = os.environ.get("CENTINELA_CENTRAL_CONF", "/etc/centinela-central/central.conf")
PKG_DIR = Path(__file__).resolve().parent

EXAMPLE = """\
# Centinela central. Tras cambiar algo: systemctl restart centinela-central

[server]
# Donde escucha. Detras de nginx o Caddy, 127.0.0.1.
listen = 127.0.0.1
port = 8470
# URL publica completa por la que llegan agentes y navegador, ruta incluida.
# Sale en las ordenes de alta y en los correos.
public_url = https://flota.ejemplo.com
# Si se sirve bajo una ruta (https://dominio/flota), esa ruta; vacio si va en la raiz.
# Tiene que coincidir con la ruta de public_url.
base_path =
# Proxies de los que se aceptan X-Forwarded-For y X-Forwarded-Proto.
trusted_proxies = 127.0.0.1
db = /var/lib/centinela-central/central.db
# Codigo fuente del agente que se reparte a los servidores nuevos.
agent_src =

[alerts]
# Segundos sin informe para dar un servidor por perdido.
offline_after = 300
# Un problema tiene que durar esto antes de avisar (evita avisos por picos).
notify_after = 300

[smtp]
# Sin host no se envia correo: las alertas solo se ven en el panel.
host =
port = 587
starttls = yes
user =
password =
from =
to =
"""


def render_example(**server) -> str:
    """El ejemplo con valores propios en [server] (solo ahi: [smtp] tambien tiene «port»)."""
    out, seccion = [], ""
    for line in EXAMPLE.splitlines(keepends=True):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            seccion = s[1:-1]
        key = s.split("=", 1)[0].strip() if "=" in s and not s.startswith("#") else ""
        if seccion == "server" and key in server and server[key] is not None:
            line = "%s = %s\n" % (key, server[key])
        out.append(line)
    return "".join(out)


class Config:
    def __init__(self, path: str = DEFAULT_FILE):
        cp = configparser.ConfigParser()
        cp.read_string(EXAMPLE)
        self.path = path
        self.loaded = bool(cp.read(path))
        s = cp["server"]
        self.listen = s.get("listen", "127.0.0.1")
        self.port = s.getint("port", 8470)
        self.public_url = s.get("public_url", "").rstrip("/")
        bp = s.get("base_path", "").strip().rstrip("/")
        self.base_path = ("/" + bp.lstrip("/")) if bp else ""
        self.trusted_proxies = s.get("trusted_proxies", "127.0.0.1")
        self.db = s.get("db", "/var/lib/centinela-central/central.db")
        src = s.get("agent_src", "").strip()
        self.agent_src = Path(src) if src else _find_agent_src()

        a = cp["alerts"]
        self.offline_after = max(60, a.getint("offline_after", 300))
        self.notify_after = max(0, a.getint("notify_after", 300))

        m = cp["smtp"]
        self.smtp = {
            "host": m.get("host", "").strip(),
            "port": m.getint("port", 587),
            "starttls": m.getboolean("starttls", True),
            "user": m.get("user", ""),
            "password": m.get("password", ""),
            "from": m.get("from", "").strip(),
            "to": [x.strip() for x in m.get("to", "").split(",") if x.strip()],
        }

    @property
    def smtp_enabled(self) -> bool:
        return bool(self.smtp["host"] and self.smtp["from"] and self.smtp["to"])


def _find_agent_src() -> Path:
    # Instalado: /opt/centinela-central/agent. En el repo: ../../agent.
    for cand in (PKG_DIR.parent / "agent", PKG_DIR.parent.parent / "agent"):
        if (cand / "centinela_agent" / "__init__.py").is_file():
            return cand
    return PKG_DIR.parent / "agent"
