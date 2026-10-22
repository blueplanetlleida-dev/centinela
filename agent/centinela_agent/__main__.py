"""centinela-agent: linea de ordenes del agente."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

from . import VERSION, config
from .collect import Sampler
from .collect.inventory import inventory, machine_id
from .daemon import build_report, deliver, run_forever, Status
from .transport import Spool, Transport, TransportError


def _need_root() -> None:
    if os.geteuid() != 0:
        sys.exit("centinela-agent: esta orden necesita root")


def cmd_run(_args) -> int:
    _need_root()
    try:
        cfg = config.load()
    except config.ConfigError as e:
        sys.exit("centinela-agent: %s" % e)
    if not cfg.enrolled:
        sys.exit("centinela-agent: el agente no está dado de alta; usa «centinela-agent enroll»")
    return run_forever(cfg)


def cmd_once(args) -> int:
    sampler = Sampler()
    sampler.prime()
    sampler.force_all()
    time.sleep(2)
    report = build_report(sampler, 0, config.DEFAULT_INTERVAL)
    if not args.send:
        json.dump(report, sys.stdout, indent=None if args.compact else 2, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0
    _need_root()
    cfg = config.load()
    if not cfg.enrolled:
        sys.exit("centinela-agent: el agente no está dado de alta")
    st = Status()
    deliver(Transport(cfg.central, cfg.token, cfg.ca_file), Spool(os.path.join(config.STATE_DIR, "spool")), report, st)
    print(json.dumps(st.data, indent=2))
    return 0 if st.data.get("last_error_at") is None or (st.data.get("last_ok") or 0) >= st.data["last_error_at"] else 1


def cmd_enroll(args) -> int:
    _need_root()
    try:
        central = config.check_url(args.central)
    except config.ConfigError as e:
        sys.exit("centinela-agent: %s" % e)
    if args.ca_file and not os.path.isfile(args.ca_file):
        sys.exit("centinela-agent: no existe %s" % args.ca_file)
    inv = inventory()
    payload = {
        "code": args.code.strip(),
        "machine_id": machine_id(),
        "hostname": inv.get("hostname"),
        "name": args.name or "",
        "inventory": inv,
        "agent": {"version": VERSION},
    }
    try:
        code, resp = Transport(central, "", args.ca_file).post("/api/v1/enroll", payload)
    except TransportError as e:
        sys.exit("centinela-agent: no se pudo contactar con %s: %s" % (central, e))
    if code != 200 or not resp.get("agent_id") or not resp.get("token"):
        sys.exit("centinela-agent: el central rechazó el alta: %s" % (resp.get("error") or "HTTP %d" % code))
    config.save(central, args.ca_file or "", args.name or "", resp["agent_id"], resp["token"],
                int(resp.get("interval") or config.DEFAULT_INTERVAL))
    print("Alta correcta: este servidor es «%s» en %s" % (resp.get("name") or inv.get("hostname"), central))
    if resp.get("replaced"):
        print("(ya estaba dado de alta: se conserva su historial y se renueva el token)")
    return 0


def cmd_status(_args) -> int:
    try:
        cfg = config.load()
    except config.ConfigError as e:
        print("configuración inválida: %s" % e)
        return 1
    st = {}
    try:
        with open(os.path.join(config.STATE_DIR, "status.json"), "r", encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        pass

    def fecha(ts):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "nunca"

    print("versión      %s" % VERSION)
    print("central      %s" % (cfg.central or "(sin configurar)"))
    print("agente       %s" % (cfg.agent_id or "(sin alta)"))
    print("intervalo    %ss" % cfg.interval)
    print("último envío %s" % fecha(st.get("last_ok")))
    if st.get("last_error_at") and (st.get("last_ok") or 0) < st["last_error_at"]:
        print("último error %s: %s" % (fecha(st["last_error_at"]), st.get("last_error")))
    print("en cola      %s informe(s)" % Spool(os.path.join(config.STATE_DIR, "spool")).count())
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="centinela-agent", description="Agente de salud de Centinela")
    p.add_argument("--version", action="version", version="centinela-agent " + VERSION)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("run", help="servicio: informa al central en bucle")
    s = sub.add_parser("once", help="recoge un informe completo y lo muestra (o lo envía con --send)")
    s.add_argument("--send", action="store_true")
    s.add_argument("--compact", action="store_true")
    s = sub.add_parser("enroll", help="da de alta este servidor en un central")
    s.add_argument("--central", required=True, help="URL del central, p. ej. https://flota.ejemplo.com")
    s.add_argument("--code", required=True, help="código de alta generado en el central")
    s.add_argument("--name", default="", help="nombre a mostrar (por defecto, el hostname)")
    s.add_argument("--ca-file", default="", help="CA propia si el central usa un certificado no público")
    sub.add_parser("status", help="estado de la conexión con el central")

    args = p.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s" if not sys.stderr.isatty() else "%(asctime)s %(levelname)s %(message)s",
    )
    cmds = {"run": cmd_run, "once": cmd_once, "enroll": cmd_enroll, "status": cmd_status}
    if args.cmd not in cmds:
        p.print_help()
        return 2
    return cmds[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
