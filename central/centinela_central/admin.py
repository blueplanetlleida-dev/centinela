"""Usuarios del panel: alta, correo y avisos de cada uno, contrasenas."""

from __future__ import annotations

import re
import time

from . import auth, db
from .mailer import valid_email

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,40}$")
MIN_PW = 10


class AdminError(Exception):
    pass


def users() -> list:
    return db.conn().execute(
        "SELECT id, username, email, notify, weekly, totp_secret IS NOT NULL AS totp, created_at"
        " FROM users ORDER BY username COLLATE NOCASE").fetchall()


def _email(email: str) -> str:
    email = (email or "").strip()
    if email and not valid_email(email):
        raise AdminError("La dirección de correo no es válida.")
    return email


def add(username: str, email: str, by: str, ip: str) -> str:
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise AdminError("Nombre de usuario no válido: de 2 a 40 letras, números, puntos, guiones o guiones bajos.")
    email = _email(email)
    if db.conn().execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        raise AdminError("Ya existe un usuario %s." % username)
    pw = auth.new_password()
    now = int(time.time())
    with db.tx() as c:
        c.execute("INSERT INTO users (username, pw_hash, created_at, email, notify, weekly) VALUES (?, ?, ?, ?, 1, 1)",
                  (username, auth.hash_password(pw), now, email or None))
        db.audit(c, now, by, ip, "user-add", username)
    return pw


def update(uid: int, email: str, notify: bool, weekly: bool, by: str, ip: str) -> None:
    email = _email(email)
    with db.tx() as c:
        c.execute("UPDATE users SET email = ?, notify = ?, weekly = ? WHERE id = ?",
                  (email or None, 1 if notify else 0, 1 if weekly else 0, uid))
        db.audit(c, int(time.time()), by, ip, "user-update", "id=%d email=%s notify=%d weekly=%d"
                 % (uid, email, notify, weekly))


def reset_password(uid: int, by: str, ip: str) -> tuple:
    u = db.conn().execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
    if u is None:
        raise AdminError("Ese usuario no existe.")
    pw = auth.new_password()
    with db.tx() as c:
        c.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (auth.hash_password(pw), uid))
        c.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        db.audit(c, int(time.time()), by, ip, "user-reset", u["username"])
    return u["username"], pw


def delete(uid: int, self_id: int, by: str, ip: str) -> None:
    if uid == self_id:
        raise AdminError("No puedes borrar tu propio usuario.")
    if db.conn().execute("SELECT COUNT(*) FROM users").fetchone()[0] <= 1:
        raise AdminError("Tiene que quedar al menos un usuario.")
    with db.tx() as c:
        u = c.execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
        c.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        c.execute("DELETE FROM users WHERE id = ?", (uid,))
        db.audit(c, int(time.time()), by, ip, "user-del", u["username"] if u else str(uid))


def change_own_password(uid: int, current: str, new: str, repeat: str, ip: str, session_hash: str) -> None:
    u = db.conn().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if u is None or not auth.verify_password(current, u["pw_hash"]):
        raise AdminError("La contraseña actual no es correcta.")
    if len(new) < MIN_PW:
        raise AdminError("La contraseña nueva necesita al menos %d caracteres." % MIN_PW)
    if new != repeat:
        raise AdminError("Las dos contraseñas nuevas no coinciden.")
    with db.tx() as c:
        c.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (auth.hash_password(new), uid))
        # Fuera las demas sesiones de este usuario; la actual sigue.
        c.execute("DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?", (uid, session_hash))
        db.audit(c, int(time.time()), u["username"], ip, "passwd", "")
