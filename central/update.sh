#!/bin/sh
# Centinela central: actualizacion desde las versiones publicadas en GitHub.
#
# La lanza cada dia centinela-central-update.timer. A mano:
#   sudo sh /opt/centinela-central/update.sh            # segun el modo de central.conf
#   sudo sh /opt/centinela-central/update.sh --check    # solo mira si hay version nueva
#   sudo sh /opt/centinela-central/update.sh --force    # actualiza aunque el modo sea «notify»
#
# Solo cuentan las versiones publicadas con etiqueta flota-vX.Y.Z (ni borradores
# ni prerreleases): publicar es la decision de desplegar, no cada commit.
# Antes de instalar guarda la version actual; si la nueva no arranca, vuelve a ella.
set -eu

PREFIX=/opt/centinela-central
CONF=/etc/centinela-central/central.conf
STATE=/var/lib/centinela-central
STATUS="$STATE/update.json"
PY="$PREFIX/venv/bin/python"
SVC_USER=centinela-central

CHECK=0
FORCE=0
for a in "$@"; do
    case "$a" in
        --check) CHECK=1 ;;
        --force) FORCE=1 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "Opción desconocida: $a" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "Hay que ejecutarlo como root." >&2; exit 1; }
[ -x "$PY" ] || { echo "No hay un central instalado en $PREFIX." >&2; exit 1; }

ini() {
    "$PY" -I -c 'import configparser, sys
c = configparser.ConfigParser()
c.read(sys.argv[1])
print(c.get(sys.argv[2], sys.argv[3], fallback=sys.argv[4]).strip())' "$CONF" "$1" "$2" "$3"
}

MODE=$(ini update mode auto)
REPO=$(ini update repo blueplanetlleida-dev/centinela)
INSTALADA=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$PREFIX/centinela_central/__init__.py")
ULTIMA=""

status() {
    # status RESULTADO DETALLE: lo lee el panel.
    "$PY" -I -c 'import json, sys, time
json.dump({"checked": int(time.time()), "installed": sys.argv[1], "latest": sys.argv[2], "mode": sys.argv[3],
           "result": sys.argv[4], "detail": sys.argv[5]}, open(sys.argv[6], "w"))' \
        "$INSTALADA" "$ULTIMA" "$MODE" "$1" "$2" "$STATUS.tmp"
    chown "$SVC_USER:$SVC_USER" "$STATUS.tmp" 2>/dev/null || true
    chmod 640 "$STATUS.tmp"
    mv "$STATUS.tmp" "$STATUS"
    echo "$2"
}

if [ "$MODE" = off ] && [ "$CHECK" = 0 ] && [ "$FORCE" = 0 ]; then
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

if ! curl -fsSL --max-time 30 -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$REPO/releases?per_page=50" -o "$TMP/releases.json"; then
    status error "No se pudo consultar GitHub ($REPO)."
    exit 1
fi

# version etiqueta paquete sumas (los dos ultimos pueden ir vacios)
SEL=$("$PY" -I -c 'import json, re, sys
rels = json.load(open(sys.argv[1]))
best = None
for r in rels if isinstance(rels, list) else []:
    m = re.fullmatch(r"flota-v(\d+)\.(\d+)\.(\d+)", r.get("tag_name") or "")
    if not m or r.get("draft") or r.get("prerelease"):
        continue
    v = tuple(int(x) for x in m.groups())
    if best is None or v > best[0]:
        best = (v, r)
if best:
    v, r = best
    ver = "%d.%d.%d" % v
    assets = {a.get("name"): a.get("browser_download_url") for a in r.get("assets") or []}
    print(ver, r["tag_name"], assets.get("centinela-flota-%s.tar.gz" % ver) or "-", assets.get("SHA256SUMS") or "-")' "$TMP/releases.json")

if [ -z "$SEL" ]; then
    status ok "No hay versiones publicadas de flota en $REPO."
    exit 0
fi
set -- $SEL
ULTIMA=$1; TAG=$2; PAQ=$3; SUMS=$4

NUEVA=$("$PY" -I -c 'import sys
n = lambda v: tuple(int(x) for x in v.split("."))
print(1 if n(sys.argv[1]) > n(sys.argv[2]) else 0)' "$ULTIMA" "${INSTALADA:-0.0.0}")
if [ "$NUEVA" = 0 ]; then
    status ok "Al día: instalada $INSTALADA, última publicada $ULTIMA."
    exit 0
fi
if [ "$CHECK" = 1 ] || { [ "$MODE" != auto ] && [ "$FORCE" = 0 ]; }; then
    status available "Hay versión nueva: $ULTIMA (instalada $INSTALADA)."
    exit 0
fi

# Descarga: el paquete de la version con su suma si lo publica; si no, el
# archivo de la etiqueta que genera GitHub (sin suma: se confia en HTTPS).
if [ "$PAQ" != "-" ]; then
    curl -fsSL --max-time 120 -o "$TMP/src.tar.gz" "$PAQ"
    if [ "$SUMS" != "-" ]; then
        curl -fsSL --max-time 30 -o "$TMP/SHA256SUMS" "$SUMS"
        ESPERADA=$(sed -n "s/^\([0-9a-f]\{64\}\)  *centinela-flota-$ULTIMA\.tar\.gz$/\1/p" "$TMP/SHA256SUMS")
        REAL=$(sha256sum "$TMP/src.tar.gz" | cut -d' ' -f1)
        if [ -z "$ESPERADA" ] || [ "$ESPERADA" != "$REAL" ]; then
            status error "La suma del paquete $ULTIMA no coincide: no se instala."
            exit 1
        fi
    fi
else
    curl -fsSL --max-time 120 -o "$TMP/src.tar.gz" "https://github.com/$REPO/archive/refs/tags/$TAG.tar.gz"
fi
mkdir "$TMP/src"
tar xzf "$TMP/src.tar.gz" -C "$TMP/src"
INST=$(find "$TMP/src" -maxdepth 3 -path '*/central/install.sh' | head -n 1)
SRC=""
[ -z "$INST" ] || SRC=$(dirname "$(dirname "$INST")")
if [ -z "$SRC" ] || [ ! -f "$SRC/central/install.sh" ] || [ ! -f "$SRC/agent/centinela_agent/__init__.py" ]; then
    status error "El paquete $ULTIMA no trae el central y el agente."
    exit 1
fi

# Copia de la version actual para volver atras si la nueva no arranca.
BACKUP="$STATE/rollback-$INSTALADA.tar.gz"
tar czf "$BACKUP" -C "$PREFIX" centinela_central agent install.sh requirements.txt 2>/dev/null || \
    tar czf "$BACKUP" -C "$PREFIX" centinela_central agent
chmod 600 "$BACKUP"

if ! sh "$SRC/central/install.sh" > "$TMP/install.log" 2>&1; then
    tail -5 "$TMP/install.log" >&2
fi

LISTEN=$(ini server listen 127.0.0.1)
PORT=$(ini server port 8470)
BASE=$(ini server base_path "")
[ "$LISTEN" = "0.0.0.0" ] && LISTEN=127.0.0.1
OK=0
i=0
while [ $i -lt 30 ]; do
    if curl -fs --max-time 3 "http://$LISTEN:$PORT$BASE/healthz" 2>/dev/null | grep -q ok; then
        OK=1
        break
    fi
    sleep 2
    i=$((i + 1))
done
NUEVA_INST=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$PREFIX/centinela_central/__init__.py")
if [ "$OK" = 1 ] && [ "$NUEVA_INST" = "$ULTIMA" ]; then
    ANTES=$INSTALADA
    INSTALADA=$NUEVA_INST
    status ok "Actualizado de $ANTES a $ULTIMA."
    exit 0
fi

# No arranca: vuelta a la version anterior.
rm -rf "$PREFIX/centinela_central" "$PREFIX/agent"
tar xzf "$BACKUP" -C "$PREFIX"
systemctl restart centinela-central || true
status error "La versión $ULTIMA no arrancó; se ha vuelto a la $INSTALADA. Registro: journalctl -u centinela-central"
exit 1
