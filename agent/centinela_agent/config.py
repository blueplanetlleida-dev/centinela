"""Configuracion (/etc/centinela-agent/agent.conf) y credenciales del agente."""

from __future__ import annotations

import configparser
import io
import json
import os
from urllib.parse import urlparse

from .util import write_atomic

CONF_DIR = os.environ.get("CENTINELA_AGENT_CONF", "/etc/centinela-agent")
STATE_DIR = os.environ.get("CENTINELA_AGENT_STATE", "/var/lib/centinela-agent")
CONF_FILE = os.path.join(CONF_DIR, "agent.conf")
CRED_FILE = os.path.join(CONF_DIR, "credentials.json")

DEFAULT_INTERVAL = 60
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class ConfigError(Exception):
    pass


class Config:
    def __init__(self):
        self.central = ""
        self.ca_file = ""
        self.interval = DEFAULT_INTERVAL
        self.name = ""
        self.agent_id = ""
        self.token = ""

    @property
    def enrolled(self) -> bool:
        return bool(self.central and self.agent_id and self.token)


def check_url(url: str) -> str:
    """El token viaja en cada envio: solo HTTPS, salvo al propio equipo."""
    u = urlparse(url.strip())
    if u.scheme not in ("https", "http") or not u.hostname:
        raise ConfigError("la URL del central debe ser https://servidor[/ruta]")
    if u.scheme == "http" and u.hostname not in LOOPBACK:
        raise ConfigError("sin HTTPS el token viajaría en claro: usa https:// (http solo vale para 127.0.0.1)")
    return url.strip().rstrip("/")


def load() -> Config:
    c = Config()
    cp = configparser.ConfigParser()
    cp.read(CONF_FILE)
    c.central = cp.get("central", "url", fallback="").strip().rstrip("/")
    c.ca_file = cp.get("central", "ca_file", fallback="").strip()
    try:
        c.interval = max(15, min(3600, cp.getint("agent", "interval", fallback=DEFAULT_INTERVAL)))
    except ValueError:
        c.interval = DEFAULT_INTERVAL
    c.name = cp.get("agent", "name", fallback="").strip()
    try:
        with open(CRED_FILE, "r", encoding="utf-8") as f:
            cred = json.load(f)
        c.agent_id = str(cred.get("agent_id", ""))
        c.token = str(cred.get("token", ""))
    except (OSError, ValueError):
        pass
    if c.central:
        c.central = check_url(c.central)
    return c


def save(central: str, ca_file: str, name: str, agent_id: str, token: str, interval: int) -> None:
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    cp = configparser.ConfigParser()
    cp["central"] = {"url": central}
    if ca_file:
        cp["central"]["ca_file"] = ca_file
    cp["agent"] = {"interval": str(interval)}
    if name:
        cp["agent"]["name"] = name
    buf = io.StringIO()
    buf.write("# Centinela, agente. Lo escribe «centinela-agent enroll»; se puede editar a mano.\n")
    cp.write(buf)
    write_atomic(CONF_FILE, buf.getvalue().encode(), 0o644)
    write_atomic(CRED_FILE, json.dumps({"agent_id": agent_id, "token": token}).encode(), 0o600)
