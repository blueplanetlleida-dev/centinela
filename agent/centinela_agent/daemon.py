"""Bucle del servicio: muestrea, compone el informe, lo entrega o lo encola."""

from __future__ import annotations

import json
import os
import signal
import threading
import time

from . import PROTOCOL, VERSION
from .collect import Sampler
from .config import STATE_DIR, Config
from .transport import Spool, Transport, TransportError
from .util import log, write_atomic

BATCH = 100          # informes por envio
CATCHUP_ROUNDS = 20  # envios extra por ciclo al vaciar la cola tras un corte


def build_report(sampler: Sampler, seq: int, interval: int) -> dict:
    errors = {}
    metrics = sampler.metrics(errors)
    sections = sampler.sections(errors)
    rep = {"v": PROTOCOL, "ts": int(time.time()), "seq": seq, "interval": interval, "metrics": metrics}
    if sections:
        rep["sections"] = sections
    if errors:
        rep["errors"] = errors
    return rep


class Status:
    """Estado para «centinela-agent status» y para no llenar el journal del mismo error."""

    def __init__(self):
        self.path = os.path.join(STATE_DIR, "status.json")
        self.data = {"last_ok": None, "last_error": None, "last_error_at": None, "spool": 0}
        self._failing = False
        self._last_log = 0.0

    def ok(self, spool: int) -> None:
        if self._failing:
            log.info("el central vuelve a responder; quedan %d informes en cola", spool)
        self._failing = False
        self.data.update(last_ok=int(time.time()), spool=spool)
        self._save()

    def fail(self, msg: str, spool: int) -> None:
        now = time.monotonic()
        if not self._failing or now - self._last_log > 1800:
            log.error("%s (en cola: %d)", msg, spool)
            self._last_log = now
        self._failing = True
        self.data.update(last_error=msg, last_error_at=int(time.time()), spool=spool)
        self._save()

    def _save(self) -> None:
        try:
            write_atomic(self.path, json.dumps(self.data).encode(), 0o600)
        except OSError:
            pass


def deliver(tr: Transport, spool: Spool, report: dict, st: Status) -> int | None:
    """Entrega lo pendiente y el informe nuevo. Devuelve el intervalo que pida el central."""
    pending = spool.batch(BATCH - 1)
    payload = {"agent": {"version": VERSION}, "reports": [r for _, r in pending] + [report]}
    try:
        code, resp = tr.post("/api/v1/report", payload)
    except TransportError as e:
        spool.put(report)
        st.fail("el central no responde: %s" % e, spool.count())
        return None

    if code == 200:
        spool.drop([f for f, _ in pending])
        # Tras un corte largo, vaciar la cola sin esperar a los siguientes ciclos.
        for _ in range(CATCHUP_ROUNDS):
            more = spool.batch(BATCH)
            if not more:
                break
            try:
                c2, _ = tr.post("/api/v1/report", {"agent": {"version": VERSION}, "reports": [r for _, r in more]})
            except TransportError:
                break
            if c2 != 200:
                break
            spool.drop([f for f, _ in more])
        st.ok(spool.count())
        iv = resp.get("interval")
        return int(iv) if isinstance(iv, int) and 15 <= iv <= 3600 else None

    detalle = resp.get("error") or "HTTP %d" % code
    if code in (401, 403):
        # Un agente revocado no va a ser aceptado: encolar solo llenaria el disco.
        st.fail("el central rechaza este agente (%s); vuelve a darlo de alta con «centinela-agent enroll»" % detalle,
                spool.count())
        return None
    if code in (400, 413, 422):
        # Lo que el central rechaza por malformado lo seguira rechazando: se descarta
        # lo pendiente para no atascar la cola para siempre.
        spool.drop([f for f, _ in pending])
        st.fail("el central rechazó el informe (%s); se descartan %d pendientes" % (detalle, len(pending)),
                spool.count())
        return None
    spool.put(report)
    st.fail("el central respondió %s" % detalle, spool.count())
    return None


def run_forever(cfg: Config) -> int:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    tr = Transport(cfg.central, cfg.token, cfg.ca_file)
    spool = Spool(os.path.join(STATE_DIR, "spool"))
    st = Status()
    sampler = Sampler()
    sampler.prime()
    log.info("centinela-agent %s: informando a %s cada %ds como %s", VERSION, cfg.central, cfg.interval, cfg.agent_id)

    interval = cfg.interval
    seq = 0
    stop.wait(3)  # primer informe casi inmediato, con tasas sobre 3 segundos
    while not stop.is_set():
        t0 = time.monotonic()
        report = build_report(sampler, seq, interval)
        seq += 1
        nuevo = deliver(tr, spool, report, st)
        if nuevo and nuevo != interval:
            log.info("el central pide informar cada %ds", nuevo)
            interval = nuevo
        stop.wait(max(1.0, interval - (time.monotonic() - t0)))
    log.info("centinela-agent detenido")
    return 0
