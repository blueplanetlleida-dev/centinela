"""Sistemas de ficheros (ocupacion e inodos) y E/S por disco fisico."""

from __future__ import annotations

import os
import threading

from ..util import read

LOCAL_FS = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs",
    "vfat", "exfat", "ntfs", "ntfs3", "fuseblk",
}
NET_FS = {"nfs", "nfs4", "cifs", "smb3", "glusterfs", "ceph", "fuse.sshfs"}
SKIP_PREFIX = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containers")
MAX_FS = 40

# Un NFS colgado deja statvfs bloqueado para siempre. Esos montajes se miran en
# un hilo con plazo y, si no responden, se dejan de mirar hasta reiniciar.
_colgados = set()


def _statvfs(path: str, net: bool):
    if not net:
        return os.statvfs(path)
    if path in _colgados:
        return None
    res = []
    t = threading.Thread(target=lambda: res.append(os.statvfs(path)), daemon=True)
    t.start()
    t.join(3)
    if t.is_alive() or not res:
        _colgados.add(path)
        return None
    return res[0]


def _unescape(s: str) -> str:
    # /proc/mounts codifica espacios y tabuladores como \040 y \011.
    return s.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")


def filesystems() -> list:
    # Los montajes del sistema, no los del servicio: con ProtectSystem=full
    # systemd remonta /boot, /usr y /etc en solo lectura dentro de nuestro
    # espacio de nombres, y se verian como «ro» sin serlo.
    raw = read("/proc/1/mounts") or read("/proc/self/mounts") or ""
    vistos = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        dev, mnt, fstype, opts = _unescape(parts[0]), _unescape(parts[1]), parts[2], parts[3]
        net = fstype in NET_FS
        if fstype not in LOCAL_FS and not net:
            continue
        if mnt != "/" and mnt.startswith(SKIP_PREFIX):
            continue
        try:
            st = os.stat(mnt) if not net else None
        except OSError:
            continue
        # Los bind mounts (Plesk tiene muchos) repiten el mismo dispositivo:
        # se queda el punto de montaje mas corto.
        clave = (st.st_dev if st else dev, fstype if fstype != "zfs" else mnt)
        prev = vistos.get(clave)
        if prev and len(prev[1]) <= len(mnt):
            continue
        vistos[clave] = (dev, mnt, fstype, opts, net)

    out = []
    for dev, mnt, fstype, opts, net in sorted(vistos.values(), key=lambda x: x[1]):
        try:
            sv = _statvfs(mnt, net)
        except OSError:
            continue
        if sv is None:
            out.append({"mount": mnt, "dev": dev, "fs": fstype, "unreachable": True})
            continue
        if sv.f_blocks == 0:
            continue
        total = sv.f_blocks * sv.f_frsize
        used = (sv.f_blocks - sv.f_bfree) * sv.f_frsize
        avail = sv.f_bavail * sv.f_frsize
        # Igual que df: el porcentaje sobre lo que puede usar un usuario normal,
        # sin contar el 5 % reservado a root.
        pct = 100.0 * used / (used + avail) if used + avail else 0.0
        ino = None
        if sv.f_files:
            ino = round(100.0 * (sv.f_files - sv.f_ffree) / sv.f_files, 1)
        out.append({
            "mount": mnt, "dev": dev, "fs": fstype,
            "total": total, "used": used, "avail": avail,
            "pct": round(pct, 1), "inodes_pct": ino,
            "ro": "ro" in opts.split(","),
        })
        if len(out) >= MAX_FS:
            break
    return out


def _fisico(name: str) -> bool:
    if name.startswith(("loop", "ram", "zram", "sr", "fd", "dm-", "md", "nbd", "rbd")):
        return False
    return os.path.exists("/sys/block/%s/device" % name)


def diskstats() -> dict:
    """Contadores acumulados por disco: (lecturas, sectores leidos, escrituras, sectores escritos, ms ocupado)."""
    out = {}
    raw = read("/proc/diskstats") or ""
    for line in raw.splitlines():
        p = line.split()
        if len(p) < 14 or not _fisico(p[2]):
            continue
        out[p[2]] = (int(p[3]), int(p[5]), int(p[7]), int(p[9]), int(p[12]))
    return out


def io_rates(prev: dict | None, cur: dict, dt: float) -> list:
    if not prev or dt <= 0:
        return []
    out = []
    for name, c in sorted(cur.items()):
        p = prev.get(name)
        if not p:
            continue
        d = [max(0, a - b) for a, b in zip(c, p)]
        out.append({
            "dev": name,
            "r_iops": round(d[0] / dt, 1),
            "r_bps": int(d[1] * 512 / dt),   # /proc/diskstats cuenta siempre sectores de 512 bytes
            "w_iops": round(d[2] / dt, 1),
            "w_bps": int(d[3] * 512 / dt),
            "util": round(min(100.0, d[4] / (dt * 10.0)), 1),
        })
    return out
