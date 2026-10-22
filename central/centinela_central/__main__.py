"""centinela-central: servicio y administracion desde la linea de ordenes."""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
import time

from . import VERSION, auth, db
from .config import DEFAULT_FILE, Config, render_example


def _db(cfg: Config) -> None:
    db.init(cfg.db)


def cmd_serve(cfg: Config, _args) -> int:
    import uvicorn
    from .web import create_app

    if not cfg.loaded:
        logging.warning("no existe %s: se usan los valores por defecto", cfg.path)
    app = create_app(cfg)
    uvicorn.run(app, host=cfg.listen, port=cfg.port, proxy_headers=True,
                forwarded_allow_ips=cfg.trusted_proxies, server_header=False, access_log=False,
                log_level="info")
    return 0


def cmd_init(cfg: Config, _args) -> int:
    _db(cfg)
    print("Base de datos lista en %s" % cfg.db)
    n = db.conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if n == 0:
        pw = auth.new_password()
        _add_user("admin", pw)
        print("Usuario creado: admin")
        print("Contraseña:     %s" % pw)
        print("(cámbiala con «centinela-central user passwd admin»)")
    return 0


def _add_user(name: str, pw: str) -> None:
    with db.tx() as c:
        c.execute("INSERT INTO users (username, pw_hash, created_at) VALUES (?, ?, ?)",
                  (name, auth.hash_password(pw), int(time.time())))


def _ask_password() -> str:
    while True:
        pw = getpass.getpass("Contraseña nueva: ")
        if len(pw) < 10:
            print("Mínimo 10 caracteres.")
            continue
        if pw != getpass.getpass("Repítela: "):
            print("No coinciden.")
            continue
        return pw


def cmd_user(cfg: Config, args) -> int:
    _db(cfg)
    c = db.conn()
    if args.action == "list":
        for u in c.execute("SELECT username, totp_secret IS NOT NULL AS totp, created_at FROM users ORDER BY username"):
            print("%-20s 2FA:%s  alta %s" % (u["username"], "sí" if u["totp"] else "no",
                                            time.strftime("%Y-%m-%d", time.localtime(u["created_at"]))))
        return 0
    if not args.name:
        sys.exit("falta el nombre de usuario")
    u = c.execute("SELECT * FROM users WHERE username = ?", (args.name,)).fetchone()
    if args.action == "add":
        if u:
            sys.exit("ya existe %s" % args.name)
        pw = auth.new_password() if args.generate else _ask_password()
        _add_user(args.name, pw)
        print("Usuario %s creado." % args.name + (" Contraseña: %s" % pw if args.generate else ""))
        return 0
    if u is None:
        sys.exit("no existe %s" % args.name)
    if args.action == "passwd":
        pw = auth.new_password() if args.generate else _ask_password()
        with db.tx() as w:
            w.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (auth.hash_password(pw), u["id"]))
            w.execute("DELETE FROM sessions WHERE user_id = ?", (u["id"],))
        print("Contraseña cambiada; sus sesiones abiertas se han cerrado." + (" Nueva: %s" % pw if args.generate else ""))
    elif args.action == "totp":
        secret = auth.new_totp_secret()
        print("Añade esta cuenta a tu aplicación de autenticación (Google Authenticator, Aegis, 1Password...):")
        print("  clave: %s" % secret)
        print("  URI:   %s" % auth.totp_uri(secret, args.name))
        code = input("Escribe el código de 6 cifras que te muestra para confirmar: ")
        step = auth.totp_check(secret, code, 0)
        if step is None:
            sys.exit("Código incorrecto: no se activa el doble factor.")
        with db.tx() as w:
            w.execute("UPDATE users SET totp_secret = ?, totp_last_step = ? WHERE id = ?", (secret, step, u["id"]))
        print("Doble factor activado para %s." % args.name)
    elif args.action == "no-totp":
        with db.tx() as w:
            w.execute("UPDATE users SET totp_secret = NULL WHERE id = ?", (u["id"],))
        print("Doble factor desactivado para %s." % args.name)
    elif args.action == "del":
        with db.tx() as w:
            w.execute("DELETE FROM sessions WHERE user_id = ?", (u["id"],))
            w.execute("DELETE FROM users WHERE id = ?", (u["id"],))
        print("Usuario %s borrado." % args.name)
    return 0


def cmd_enroll_code(cfg: Config, args) -> int:
    _db(cfg)
    from .views import create_code
    code = create_code(args.label or "", args.ttl * 3600, "cli", "local")
    print(code)
    if cfg.public_url:
        print()
        print("En el servidor nuevo, como root:")
        print("  curl -fsSL %s/dl/install.sh -o centinela-install.sh" % cfg.public_url)
        print("  sudo sh centinela-install.sh --code %s" % code)
    return 0


def cmd_hosts(cfg: Config, _args) -> int:
    _db(cfg)
    now = int(time.time())
    for h in db.conn().execute("SELECT * FROM hosts ORDER BY name COLLATE NOCASE"):
        visto = "nunca" if not h["last_seen"] else "hace %ds" % (now - h["last_seen"])
        print("%-14s %-24s %-9s %s" % (h["id"], h["name"][:24], h["status"], visto))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="centinela-central", description="Centinela central")
    p.add_argument("--version", action="version", version="centinela-central " + VERSION)
    p.add_argument("-c", "--config", default=DEFAULT_FILE, help="fichero de configuración (%(default)s)")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="arranca el servicio web")
    sub.add_parser("init", help="crea la base de datos y, si no hay usuarios, el usuario admin")
    s = sub.add_parser("example-config", help="muestra una configuración de ejemplo")
    s.add_argument("--url", dest="public_url")
    s.add_argument("--base-path", dest="base_path")
    s.add_argument("--port")
    s.add_argument("--listen")
    s = sub.add_parser("user", help="usuarios del panel")
    s.add_argument("action", choices=["list", "add", "passwd", "totp", "no-totp", "del"])
    s.add_argument("name", nargs="?")
    s.add_argument("--generate", action="store_true", help="genera la contraseña en vez de pedirla")
    s = sub.add_parser("enroll-code", help="genera un código de alta para un servidor")
    s.add_argument("--label", default="")
    s.add_argument("--ttl", type=int, default=24, help="horas de validez (por defecto 24)")
    sub.add_parser("hosts", help="lista los servidores")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if args.cmd == "example-config":
        bp = args.base_path
        if bp:
            bp = "/" + bp.strip("/")
        sys.stdout.write(render_example(public_url=(args.public_url or "").rstrip("/") or None,
                                        base_path=bp, port=args.port, listen=args.listen))
        return 0
    cmds = {"serve": cmd_serve, "init": cmd_init, "user": cmd_user, "enroll-code": cmd_enroll_code, "hosts": cmd_hosts}
    if args.cmd not in cmds:
        p.print_help()
        return 2
    return cmds[args.cmd](Config(args.config), args)


if __name__ == "__main__":
    sys.exit(main())
