#!/bin/sh
# Centinela, agente: instalador.
#
# Desde el central (lo normal):
#   curl -fsSL https://CENTRAL/dl/install.sh -o centinela-install.sh
#   sudo sh centinela-install.sh --code XXXX-XXXX-XXXX
#
# Desde una copia del repositorio:
#   sudo sh agent/install.sh --central https://CENTRAL --code XXXX-XXXX-XXXX
#
# Volver a ejecutarlo sin --code actualiza el agente y conserva el alta.
set -eu

CENTRAL_DEFAULT="@CENTRAL_URL@"
BUNDLE_SHA256="@BUNDLE_SHA256@"
case "$CENTRAL_DEFAULT" in @*) CENTRAL_DEFAULT="" ;; esac
case "$BUNDLE_SHA256" in @*) BUNDLE_SHA256="" ;; esac

PREFIX=/opt/centinela-agent
CONF_DIR=/etc/centinela-agent
LAUNCHER=/usr/local/sbin/centinela-agent
UNIT=/etc/systemd/system/centinela-agent.service

CENTRAL="$CENTRAL_DEFAULT"
CODE=""
NAME=""
CA_FILE=""
ACTION=install

usage() {
    cat <<'EOF'
Uso: install.sh [--code CÓDIGO] [--central URL] [--name NOMBRE] [--ca-file FICHERO]
       install.sh --uninstall [--purge]

  --code       código de alta generado en el central (obligatorio la primera vez)
  --central    URL del central (ya viene puesta si el script se descargó de él)
  --name       nombre con el que aparecerá el servidor (por defecto, el hostname)
  --ca-file    CA propia, si el central usa un certificado que no es público
  --uninstall  quita el agente; con --purge borra también su configuración y su alta
EOF
}

PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --code) CODE="${2:-}"; shift 2 ;;
        --central) CENTRAL="${2:-}"; shift 2 ;;
        --name) NAME="${2:-}"; shift 2 ;;
        --ca-file) CA_FILE="${2:-}"; shift 2 ;;
        --uninstall) ACTION=uninstall; shift ;;
        --purge) PURGE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Opción desconocida: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" != 0 ]; then
    echo "Hay que ejecutarlo como root (sudo sh $0 ...)." >&2
    exit 1
fi

if [ "$ACTION" = uninstall ]; then
    systemctl disable --now centinela-agent 2>/dev/null || true
    rm -f "$UNIT" "$LAUNCHER"
    rm -rf "$PREFIX" /var/lib/centinela-agent
    [ "$PURGE" = 1 ] && rm -rf "$CONF_DIR"
    systemctl daemon-reload 2>/dev/null || true
    echo "Agente desinstalado.$( [ "$PURGE" = 1 ] || printf ' La configuración sigue en %s (bórrala con --purge).' "$CONF_DIR")"
    echo "Recuerda borrar el servidor en el central si no va a volver."
    exit 0
fi

if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    echo "Este instalador necesita systemd." >&2
    exit 1
fi

# Python 3.8 o superior, el del sistema: el agente no usa nada fuera de la libreria estandar.
PY=""
for c in python3 /usr/bin/python3 /usr/libexec/platform-python python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
    p=$(command -v "$c" 2>/dev/null || true)
    [ -n "$p" ] || continue
    if "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
        PY="$p"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "Falta Python 3.8 o superior. Instálalo (apt install python3, o dnf install python3) y repite." >&2
    exit 1
fi

if [ -n "$CA_FILE" ]; then
    [ -f "$CA_FILE" ] || { echo "No existe $CA_FILE" >&2; exit 1; }
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    if [ "$CA_FILE" != "$CONF_DIR/ca.pem" ]; then
        cp "$CA_FILE" "$CONF_DIR/ca.pem"
        chmod 644 "$CONF_DIR/ca.pem"
    fi
    CA_FILE="$CONF_DIR/ca.pem"
fi

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
TMP=""
cleanup() { [ -z "$TMP" ] || rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

if [ ! -f "$SRC_DIR/centinela_agent/__init__.py" ]; then
    if [ -z "$CENTRAL" ]; then
        echo "Indica el central con --central https://..." >&2
        exit 1
    fi
    TMP=$(mktemp -d)
    URL="$CENTRAL/dl/centinela-agent.tar.gz"
    echo "Descargando el agente de $CENTRAL ..."
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$CA_FILE" ]; then curl -fsSL --cacert "$CA_FILE" -o "$TMP/agent.tgz" "$URL"
        else curl -fsSL -o "$TMP/agent.tgz" "$URL"; fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$CA_FILE" ]; then wget -q --ca-certificate="$CA_FILE" -O "$TMP/agent.tgz" "$URL"
        else wget -q -O "$TMP/agent.tgz" "$URL"; fi
    else
        "$PY" -I -c 'import ssl, sys, urllib.request
ctx = ssl.create_default_context(cafile=sys.argv[3] or None)
with urllib.request.urlopen(sys.argv[1], timeout=60, context=ctx) as r, open(sys.argv[2], "wb") as f:
    f.write(r.read())' "$URL" "$TMP/agent.tgz" "$CA_FILE"
    fi
    if [ -n "$BUNDLE_SHA256" ]; then
        GOT=$("$PY" -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$TMP/agent.tgz")
        if [ "$GOT" != "$BUNDLE_SHA256" ]; then
            echo "El paquete descargado no coincide con la suma esperada; no se instala nada." >&2
            exit 1
        fi
    fi
    tar xzf "$TMP/agent.tgz" -C "$TMP"
    SRC_DIR="$TMP/centinela-agent"
fi

# Copia del codigo: se monta al lado y se cambia de golpe, para que un servicio
# en marcha nunca vea medio arbol nuevo y medio viejo.
mkdir -p "$PREFIX"
rm -rf "$PREFIX/centinela_agent.new" "$PREFIX/centinela_agent.old"
cp -R "$SRC_DIR/centinela_agent" "$PREFIX/centinela_agent.new"
find "$PREFIX/centinela_agent.new" -name __pycache__ -type d -prune -exec rm -rf {} +
[ -d "$PREFIX/centinela_agent" ] && mv "$PREFIX/centinela_agent" "$PREFIX/centinela_agent.old"
mv "$PREFIX/centinela_agent.new" "$PREFIX/centinela_agent"
rm -rf "$PREFIX/centinela_agent.old"
# El propio instalador se queda en el servidor para actualizar o desinstalar.
if [ -f "$SRC_DIR/install.sh" ]; then
    sed -e "s|@CENTRAL_URL@|$CENTRAL|" "$SRC_DIR/install.sh" > "$PREFIX/install.sh"
fi
chown -R root:root "$PREFIX"
chmod -R u=rwX,go=rX "$PREFIX"

# -I aisla de variables de entorno y del directorio actual: el agente corre como root.
cat > "$LAUNCHER" <<EOF
#!$PY -I
import sys
sys.path.insert(0, "$PREFIX")
from centinela_agent.__main__ import main
sys.exit(main())
EOF
chmod 755 "$LAUNCHER"

cp "$SRC_DIR/centinela-agent.service" "$UNIT"
chmod 644 "$UNIT"
systemctl daemon-reload

if [ -n "$CODE" ]; then
    if [ -z "$CENTRAL" ]; then
        echo "Indica el central con --central https://..." >&2
        exit 1
    fi
    set -- enroll --central "$CENTRAL" --code "$CODE"
    [ -z "$NAME" ] || set -- "$@" --name "$NAME"
    [ -z "$CA_FILE" ] || set -- "$@" --ca-file "$CA_FILE"
    "$LAUNCHER" "$@"
elif [ ! -f "$CONF_DIR/credentials.json" ]; then
    echo "Agente instalado, pero falta darlo de alta: repite con --code CÓDIGO (lo genera el central)." >&2
    exit 1
fi

systemctl enable centinela-agent >/dev/null 2>&1
systemctl restart centinela-agent
sleep 5
"$LAUNCHER" status || true
echo
echo "Listo. Registro del servicio: journalctl -u centinela-agent -f"
