"""Usuarios, sesiones, CSRF, doble factor (TOTP) y tokens de agente."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

from . import db

SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
SESSION_IDLE = 12 * 3600
SESSION_MAX = 7 * 86400
LOGIN_MAX_FAILS = 10       # por IP en 15 minutos
LOGIN_WINDOW = 900


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ------------------------------------------------------------- contrasenas

def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, dklen=32, maxmem=64 * 1024 * 1024, **SCRYPT)
    return "scrypt$%d$%d$%d$%s$%s" % (SCRYPT["n"], SCRYPT["r"], SCRYPT["p"],
                                      base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(pw: str, stored: str) -> bool:
    try:
        alg, n, r, p, salt, dk = stored.split("$")
        if alg != "scrypt":
            return False
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(base64.b64decode(dk)), maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


# Mismo coste que una verificacion real, para que un usuario inexistente no se
# delate por responder antes.
_DUMMY = None


def dummy_verify(pw: str) -> None:
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(secrets.token_hex(8))
    verify_password(pw, _DUMMY)


def new_password() -> str:
    return secrets.token_urlsafe(15)


# ------------------------------------------------------------- TOTP (RFC 6238)

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_check(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Devuelve el paso aceptado (para impedir reutilizar el codigo) o None."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != 6:
        return None
    step = int((now or time.time()) // 30)
    for s in (step - 1, step, step + 1):
        if s > last_step and hmac.compare_digest(_hotp(secret, s), code):
            return s
    return None


def totp_uri(secret: str, user: str, issuer: str = "Centinela") -> str:
    from urllib.parse import quote
    return "otpauth://totp/%s:%s?secret=%s&issuer=%s" % (quote(issuer), quote(user), secret, quote(issuer))


# ------------------------------------------------------------- inicio de sesion

def too_many_fails(ip: str, now: int) -> bool:
    n = db.conn().execute("SELECT COUNT(*) FROM login_fail WHERE ip = ? AND ts > ?", (ip, now - LOGIN_WINDOW)).fetchone()[0]
    return n >= LOGIN_MAX_FAILS


def record_fail(ip: str, now: int) -> None:
    with db.tx() as c:
        c.execute("INSERT INTO login_fail (ip, ts) VALUES (?, ?)", (ip, now))


def login(username: str, password: str, code: str, ip: str, now: int) -> tuple:
    """(user_row, None) si entra; (None, motivo) si no. El motivo nunca distingue usuario de contrasena."""
    if too_many_fails(ip, now):
        return None, "Demasiados intentos fallidos. Espera unos minutos."
    u = db.conn().execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if u is None:
        dummy_verify(password)
        record_fail(ip, now)
        return None, "Usuario o contraseña incorrectos."
    if not verify_password(password, u["pw_hash"]):
        record_fail(ip, now)
        return None, "Usuario o contraseña incorrectos."
    if u["totp_secret"]:
        step = totp_check(u["totp_secret"], code, u["totp_last_step"], now)
        if step is None:
            record_fail(ip, now)
            return None, "Código de verificación incorrecto o ya usado."
        with db.tx() as c:
            c.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, u["id"]))
    return u, None


def create_session(user_id: int, ip: str, now: int) -> str:
    token = secrets.token_urlsafe(32)
    with db.tx() as c:
        c.execute("INSERT INTO sessions (id_hash, user_id, csrf, created_at, seen_at, ip) VALUES (?, ?, ?, ?, ?, ?)",
                  (sha256(token), user_id, secrets.token_urlsafe(24), now, now, ip))
        db.audit(c, now, None, ip, "login", "user_id=%d" % user_id)
    return token


def get_session(token: str | None, now: int):
    """Fila de sesion con el usuario, o None si no existe o ha caducado."""
    if not token:
        return None
    row = db.conn().execute(
        "SELECT s.*, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?",
        (sha256(token),)).fetchone()
    if row is None:
        return None
    if now - row["seen_at"] > SESSION_IDLE or now - row["created_at"] > SESSION_MAX:
        drop_session(token)
        return None
    if now - row["seen_at"] > 60:
        with db.tx() as c:
            c.execute("UPDATE sessions SET seen_at = ? WHERE id_hash = ?", (now, row["id_hash"]))
    return row


def drop_session(token: str | None) -> None:
    if token:
        with db.tx() as c:
            c.execute("DELETE FROM sessions WHERE id_hash = ?", (sha256(token),))


# ------------------------------------------------------------- agentes

def new_agent_token() -> str:
    return "cna_" + secrets.token_urlsafe(32)


def new_enroll_code() -> str:
    # Sin caracteres que se confundan al dictarlo o copiarlo a mano (0/O, 1/I).
    alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alfabeto) for _ in range(12))
    return "-".join(raw[i:i + 4] for i in range(0, 12, 4))


def norm_code(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def host_by_token(token: str | None):
    if not token or not token.startswith("cna_"):
        return None
    return db.conn().execute("SELECT * FROM hosts WHERE token_hash = ?", (sha256(token),)).fetchone()
