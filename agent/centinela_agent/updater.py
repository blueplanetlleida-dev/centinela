"""Actualizacion automatica desde el central.

El central anuncia en cada respuesta que version del agente reparte y su
SHA-256. Si es mas nueva que la instalada, se descarga del propio central, se
comprueba la suma, se desempaqueta validando cada ruta y se ejecuta su
install.sh en una unidad transitoria de systemd: el servicio del agente no
puede escribir en /usr ni en /etc (ProtectSystem), y ademas el reinicio lo
mataria a mitad de la actualizacion.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import time

from . import VERSION
from .config import STATE_DIR
from .util import log, which, write_atomic

RETRY = 6 * 3600          # si una version falla, no se reintenta hasta pasado este tiempo
MAX_BUNDLE = 20 * 1024 * 1024
UNIT = "centinela-agent-update"


def vnum(v: str) -> tuple:
    parts = [int(x) for x in re.findall(r"\d+", v or "")[:3]]
    return tuple(parts + [0] * (3 - len(parts)))


def _safe_extract(data: bytes, dest: str) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t.getmembers():
            partes = m.name.split("/")
            if (m.name.startswith("/") or ".." in partes or partes[0] != "centinela-agent"
                    or not (m.isfile() or m.isdir())):
                raise ValueError("ruta no permitida en el paquete: %s" % m.name)
        if hasattr(tarfile, "data_filter"):
            t.extractall(dest, filter="data")
        else:
            t.extractall(dest)


class Updater:
    def __init__(self, transport):
        self.tr = transport
        self.state_file = os.path.join(STATE_DIR, "update.json")
        self.dir = os.path.join(STATE_DIR, "update")

    def _state(self) -> dict:
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                v = json.load(f)
                return v if isinstance(v, dict) else {}
        except (OSError, ValueError):
            return {}

    def check(self, info) -> None:
        if not isinstance(info, dict):
            return
        ver = str(info.get("version") or "")
        sha = str(info.get("sha256") or "").lower()
        path = str(info.get("path") or "/dl/centinela-agent.tar.gz")
        if not re.fullmatch(r"\d+\.\d+\.\d+", ver) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            return
        if not path.startswith("/dl/") or ".." in path:
            return
        if vnum(ver) <= vnum(VERSION):
            return
        st = self._state()
        if st.get("version") == ver and time.time() - float(st.get("at") or 0) < RETRY:
            return
        try:
            write_atomic(self.state_file, json.dumps({"version": ver, "at": int(time.time())}).encode(), 0o600)
        except OSError:
            return
        try:
            self._apply(ver, sha, path)
        except Exception as e:  # una actualizacion fallida no debe parar los informes
            log.error("no se pudo actualizar a %s: %s", ver, e)

    def _apply(self, ver: str, sha: str, path: str) -> None:
        if not which("systemd-run"):
            raise RuntimeError("falta systemd-run")
        code, data = self.tr.get(path, timeout=120, max_bytes=MAX_BUNDLE)
        if code != 200 or not data:
            raise RuntimeError("el central respondió %s al descargar el paquete" % code)
        if hashlib.sha256(data).hexdigest() != sha:
            raise RuntimeError("la suma SHA-256 del paquete no coincide")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir, mode=0o700)
        _safe_extract(data, self.dir)
        script = os.path.join(self.dir, "centinela-agent", "install.sh")
        if not os.path.isfile(script):
            raise RuntimeError("el paquete no trae install.sh")
        log.info("actualizando el agente de %s a %s", VERSION, ver)
        p = subprocess.run(["systemd-run", "--unit=" + UNIT, "--collect", "--quiet",
                            "--description=Centinela - actualizacion del agente", "/bin/sh", script],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        if p.returncode != 0:
            raise RuntimeError("systemd-run: %s" % p.stdout.decode("utf-8", "replace").strip()[:300])
