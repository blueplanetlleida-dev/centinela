"""SQLite: esquema, conexiones por hilo y transacciones cortas.

Para decenas de servidores informando cada minuto sobra: WAL deja leer al
panel mientras entra un informe, y cada escritura es una transaccion breve.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS hosts (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    hostname      TEXT,
    machine_id    TEXT,
    token_hash    TEXT UNIQUE,
    created_at    INTEGER NOT NULL,
    last_seen     INTEGER,
    last_ip       TEXT,
    agent_version TEXT,
    interval      INTEGER NOT NULL DEFAULT 60,
    skew          INTEGER,
    status        TEXT NOT NULL DEFAULT 'new',
    state         TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS hosts_machine ON hosts(machine_id);

-- res 0: cada informe (48 h); 1: medias de 5 min (35 dias); 2: medias de 1 h (400 dias)
CREATE TABLE IF NOT EXISTS series (
    host_id TEXT NOT NULL,
    res     INTEGER NOT NULL,
    ts      INTEGER NOT NULL,
    cpu REAL, iowait REAL, steal REAL, load REAL, mem REAL, swap REAL, disk REAL,
    rx REAL, tx REAL, rd REAL, wr REAL, temp REAL,
    PRIMARY KEY (host_id, res, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id        TEXT NOT NULL,
    key            TEXT NOT NULL,
    sev            TEXT NOT NULL,
    title          TEXT NOT NULL,
    detail         TEXT NOT NULL DEFAULT '',
    opened_at      INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    closed_at      INTEGER,
    notified       INTEGER NOT NULL DEFAULT 0,  -- 0 pendiente, 1 avisado, 2 no se avisa
    notified_close INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_one_open ON alerts(host_id, key) WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS alerts_host ON alerts(host_id, opened_at);

CREATE TABLE IF NOT EXISTS enroll_codes (
    code_hash  TEXT PRIMARY KEY,
    label      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    host_id    TEXT,
    created_by TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT UNIQUE NOT NULL,
    pw_hash        TEXT NOT NULL,
    totp_secret    TEXT,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id_hash    TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    csrf       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    seen_at    INTEGER NOT NULL,
    ip         TEXT
);

CREATE TABLE IF NOT EXISTS login_fail (ip TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS login_fail_ip ON login_fail(ip, ts);

-- Ajustes editables desde el panel (avisos, correo...), en JSON.
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS audit (
    ts     INTEGER NOT NULL,
    user   TEXT,
    ip     TEXT,
    action TEXT NOT NULL,
    detail TEXT
);
"""

_local = threading.local()
_path = None


def init(path: str) -> None:
    global _path
    _path = path
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, mode=0o750, exist_ok=True)
    c = conn()
    c.executescript(SCHEMA)
    _migrate(c)
    c.execute("INSERT INTO meta(key, value) VALUES ('schema', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
              (str(SCHEMA_VERSION),))


# Columnas que llegaron despues de la primera version: se anaden a las bases
# existentes sin tocar sus datos.
COLUMNS = {
    "users": [("email", "TEXT"), ("notify", "INTEGER NOT NULL DEFAULT 1"), ("weekly", "INTEGER NOT NULL DEFAULT 1")],
}


def _migrate(c: sqlite3.Connection) -> None:
    for table, cols in COLUMNS.items():
        existentes = {r[1] for r in c.execute("PRAGMA table_info(%s)" % table)}
        for name, decl in cols:
            if name not in existentes:
                c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, decl))


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        if _path is None:
            raise RuntimeError("db.init() no se ha llamado")
        c = sqlite3.connect(_path, timeout=15, isolation_level=None, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA busy_timeout=15000")
        c.execute("PRAGMA foreign_keys=ON")
        _local.conn = c
    return c


@contextlib.contextmanager
def tx():
    """Transaccion de escritura: BEGIN IMMEDIATE evita interbloqueos entre escritores."""
    c = conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c
    except BaseException:
        c.execute("ROLLBACK")
        raise
    c.execute("COMMIT")


def meta_get(key: str, default: str | None = None) -> str | None:
    row = conn().execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(c: sqlite3.Connection, key: str, value) -> None:
    c.execute("INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
              (key, str(value)))


def audit(c: sqlite3.Connection, ts: int, user: str | None, ip: str | None, action: str, detail: str = "") -> None:
    c.execute("INSERT INTO audit(ts, user, ip, action, detail) VALUES (?, ?, ?, ?, ?)",
              (ts, user, ip, action, detail[:500]))
