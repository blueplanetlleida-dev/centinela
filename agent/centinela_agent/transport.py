"""Envio al central por HTTPS y cola en disco para cuando no responde."""

from __future__ import annotations

import gzip
import json
import os
import socket
import ssl
import urllib.error
import urllib.request

from . import VERSION
from .util import log, write_atomic


class TransportError(Exception):
    pass


class Transport:
    def __init__(self, central: str, token: str = "", ca_file: str = ""):
        self.central = central.rstrip("/")
        self.token = token
        self.ctx = ssl.create_default_context(cafile=ca_file or None)

    def post(self, path: str, payload: dict, timeout: float = 20) -> tuple:
        """Devuelve (codigo_http, cuerpo_json_o_{}); lanza TransportError si no hay respuesta."""
        body = gzip.compress(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "User-Agent": "centinela-agent/" + VERSION,
            "Accept": "application/json",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.central + path, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
                return r.status, _json(r.read(1 << 20))
        except urllib.error.HTTPError as e:
            return e.code, _json(e.read(1 << 16))
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
            raise TransportError(str(getattr(e, "reason", e)))

    def get(self, path: str, timeout: float = 60, max_bytes: int = 20 * 1024 * 1024) -> tuple:
        """(codigo_http, bytes). Para descargar el paquete de actualizacion."""
        headers = {"User-Agent": "centinela-agent/" + VERSION}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.central + path, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
                data = r.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise TransportError("la descarga supera %d bytes" % max_bytes)
                return r.status, data
        except urllib.error.HTTPError as e:
            return e.code, b""
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
            raise TransportError(str(getattr(e, "reason", e)))


def _json(raw: bytes) -> dict:
    try:
        v = json.loads(raw.decode("utf-8", "replace"))
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


class Spool:
    """Informes que no se pudieron entregar, uno por fichero, en orden de llegada.

    Acotada: con el central caido dos dias se descartan los mas antiguos antes
    que llenar el disco del servidor vigilado.
    """

    def __init__(self, directory: str, max_files: int = 2880):
        self.dir = directory
        self.max = max_files
        os.makedirs(self.dir, mode=0o700, exist_ok=True)

    def _files(self) -> list:
        try:
            return sorted(f for f in os.listdir(self.dir) if f.endswith(".json"))
        except OSError:
            return []

    def count(self) -> int:
        return len(self._files())

    def put(self, report: dict) -> None:
        report = dict(report, spooled=True)
        name = "%010d-%08d.json" % (int(report.get("ts", 0)), int(report.get("seq", 0)))
        try:
            write_atomic(os.path.join(self.dir, name), json.dumps(report, separators=(",", ":")).encode())
        except OSError as e:
            log.error("no se pudo guardar el informe en la cola: %s", e)
            return
        files = self._files()
        for f in files[: max(0, len(files) - self.max)]:
            self._rm(f)

    def batch(self, n: int) -> list:
        out = []
        for f in self._files()[:n]:
            try:
                with open(os.path.join(self.dir, f), "r", encoding="utf-8") as fh:
                    out.append((f, json.load(fh)))
            except (OSError, ValueError):
                self._rm(f)  # corrupto: no se va a poder enviar nunca
        return out

    def drop(self, names: list) -> None:
        for f in names:
            self._rm(f)

    def _rm(self, name: str) -> None:
        try:
            os.unlink(os.path.join(self.dir, name))
        except OSError:
            pass
