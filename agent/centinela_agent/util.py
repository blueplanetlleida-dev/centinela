"""Utilidades comunes: lectura tolerante de /proc y /sys, y ejecucion acotada."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile

log = logging.getLogger("centinela")

# systemd arranca los servicios con un PATH corto; smartctl, ipmitool y
# compania viven a menudo en sbin.
_PATH_EXTRA = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def read(path: str, default: str | None = None) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def read_int(path: str) -> int | None:
    raw = read(path)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def which(name: str) -> str | None:
    return shutil.which(name, path=os.environ.get("PATH", "") + ":" + _PATH_EXTRA)


def run(argv: list, timeout: float = 20) -> tuple:
    """Ejecuta sin shell. Devuelve (codigo, stdout); 127 si no existe, 124 si caduca."""
    exe = argv[0] if os.path.isabs(argv[0]) else which(argv[0])
    if not exe:
        return 127, ""
    env = dict(os.environ, LC_ALL="C", LANG="C", PATH=_PATH_EXTRA)
    try:
        p = subprocess.run(
            [exe] + list(argv[1:]),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        log.warning("%s no terminó en %ss", argv[0], timeout)
        return 124, ""
    except OSError as e:
        log.warning("no se pudo ejecutar %s: %s", argv[0], e)
        return 126, ""
    return p.returncode, p.stdout.decode("utf-8", "replace")


def run_json(argv: list, timeout: float = 20):
    """Como run(), pero interpreta la salida como JSON (None si no lo es)."""
    rc, out = run(argv, timeout)
    if not out.strip():
        return rc, None
    try:
        return rc, json.loads(out)
    except ValueError:
        return rc, None


def write_atomic(path: str, data: bytes, mode: int = 0o600) -> None:
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def round_or_none(v, nd: int = 1):
    return None if v is None else round(v, nd)
