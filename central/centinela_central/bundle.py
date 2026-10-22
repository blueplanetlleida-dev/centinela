"""Paquete del agente que reparte el central: tar.gz y script de instalacion.

Se construye en memoria al arrancar a partir del codigo del agente que va con
el central, y el instalador lleva dentro la URL del central y la suma SHA-256
del paquete, para que lo descargado se compruebe antes de instalarlo.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

from . import VERSION


class Bundle:
    def __init__(self, agent_src: Path, public_url: str):
        self.src = agent_src
        self.public_url = public_url
        self.tar = b""
        self.sha256 = ""
        self.version = ""
        self.error = ""
        try:
            self._build()
        except OSError as e:
            self.error = "no se pudo empaquetar el agente desde %s: %s" % (agent_src, e)

    def _build(self) -> None:
        pkg = self.src / "centinela_agent"
        files = sorted(p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts)
        files += [self.src / "install.sh", self.src / "centinela-agent.service"]
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as tar:
            for f in files:
                info = tar.gettarinfo(str(f), arcname="centinela-agent/" + f.relative_to(self.src).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0  # mismo contenido, misma suma, se reconstruya cuando se reconstruya
                with open(f, "rb") as fh:
                    tar.addfile(info, fh)
        self.tar = buf.getvalue()
        self.sha256 = hashlib.sha256(self.tar).hexdigest()
        for line in (pkg / "__init__.py").read_text(encoding="utf-8").splitlines():
            if line.startswith("VERSION"):
                self.version = line.split("=", 1)[1].strip().strip('"')

    def install_script(self) -> str:
        raw = (self.src / "install.sh").read_text(encoding="utf-8")
        return (raw.replace("@CENTRAL_URL@", self.public_url)
                   .replace("@BUNDLE_SHA256@", self.sha256)
                   .replace("@CENTRAL_VERSION@", VERSION))
