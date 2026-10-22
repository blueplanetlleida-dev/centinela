#!/bin/sh
# Centinela central: instalador.
#
#   sudo sh central/install.sh --url https://flota.ejemplo.com
#   sudo sh central/install.sh --url https://dominio.com/flota --base-path /flota
#
# Necesita systemd y Python 3.9 o superior con el modulo venv. Volver a
# ejecutarlo actualiza el codigo y conserva la configuracion y los datos.
set -eu

PREFIX=/opt/centinela-central
CONF_DIR=/etc/centinela-central
CONF="$CONF_DIR/central.conf"
STATE=/var/lib/centinela-central
SVC_USER=centinela-central
UNIT=/etc/systemd/system/centinela-central.service
LAUNCHER=/usr/local/sbin/centinela-central

URL=""
BASE=""
PORT=8470
LISTEN=127.0.0.1

usage() {
    cat <<'EOF'
Uso: install.sh --url URL_PUBLICA [--base-path /ruta] [--port 8470] [--listen 127.0.0.1]

  --url        URL por la que llegarán agentes y navegador, ruta incluida
  --base-path  ruta bajo la que se sirve (por defecto, la raíz)
  --port       puerto local (por defecto 8470)
  --listen     dirección en la que escucha (por defecto 127.0.0.1, detrás de nginx o Caddy)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="${2:-}"; shift 2 ;;
        --base-path) BASE="${2:-}"; shift 2 ;;
        --port) PORT="${2:-}"; shift 2 ;;
        --listen) LISTEN="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Opción desconocida: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "Hay que ejecutarlo como root." >&2; exit 1; }
if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    echo "Este instalador necesita systemd." >&2
    exit 1
fi

PY=""
for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
    p=$(command -v "$c" 2>/dev/null || true)
    [ -n "$p" ] || continue
    if "$p" -c 'import sys, venv; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
        PY="$p"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "Falta Python 3.9 o superior con venv (Debian/Ubuntu: apt install python3 python3-venv)." >&2
    exit 1
fi

SRC=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$SRC/central/centinela_central/__init__.py" ] && [ -f "$SRC/agent/centinela_agent/__init__.py" ] || {
    echo "Ejecútalo desde una copia del repositorio (faltan central/ o agent/)." >&2
    exit 1
}

if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

# Codigo: se monta al lado y se cambia de golpe.
mkdir -p "$PREFIX"
for d in centinela_central agent; do
    rm -rf "$PREFIX/$d.new" "$PREFIX/$d.old"
done
cp -R "$SRC/central/centinela_central" "$PREFIX/centinela_central.new"
mkdir -p "$PREFIX/agent.new"
cp -R "$SRC/agent/centinela_agent" "$SRC/agent/install.sh" "$SRC/agent/centinela-agent.service" "$PREFIX/agent.new/"
find "$PREFIX" -name __pycache__ -type d -prune -exec rm -rf {} +
for d in centinela_central agent; do
    [ -d "$PREFIX/$d" ] && mv "$PREFIX/$d" "$PREFIX/$d.old"
    mv "$PREFIX/$d.new" "$PREFIX/$d"
    rm -rf "$PREFIX/$d.old"
done
cp "$SRC/central/requirements.txt" "$PREFIX/requirements.txt"

if [ ! -x "$PREFIX/venv/bin/python" ]; then
    echo "Creando el entorno de Python ..."
    "$PY" -m venv "$PREFIX/venv"
fi
"$PREFIX/venv/bin/pip" install -q --disable-pip-version-check -r "$PREFIX/requirements.txt"
chown -R root:root "$PREFIX"
chmod -R u=rwX,go=rX "$PREFIX"

mkdir -p "$STATE" "$CONF_DIR"
chown "$SVC_USER:$SVC_USER" "$STATE"
chmod 750 "$STATE"

if [ ! -f "$CONF" ]; then
    if [ -z "$URL" ]; then
        echo "Primera instalación: indica la URL pública con --url https://..." >&2
        exit 1
    fi
    (cd "$PREFIX" && "$PREFIX/venv/bin/python" -m centinela_central example-config \
        --url "$URL" --base-path "$BASE" --port "$PORT" --listen "$LISTEN" > "$CONF.tmp")
    mv "$CONF.tmp" "$CONF"
    echo "Configuración creada en $CONF"
elif [ -n "$URL" ]; then
    echo "Ya existe $CONF: no se toca (edítalo a mano si quieres cambiar la URL)."
fi
chown root:"$SVC_USER" "$CONF_DIR" "$CONF"
chmod 750 "$CONF_DIR"
chmod 640 "$CONF"

cat > "$LAUNCHER" <<EOF
#!/bin/sh
# Centinela central: administracion. Corre como $SVC_USER para no dejar ficheros de root en su estado.
cd /
exec runuser -u $SVC_USER -- env PYTHONPATH=$PREFIX $PREFIX/venv/bin/python -m centinela_central -c $CONF "\$@"
EOF
chmod 755 "$LAUNCHER"

cat > "$UNIT" <<EOF
[Unit]
Description=Centinela central - panel de la flota
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$PREFIX
Environment=PYTHONPATH=$PREFIX
ExecStart=$PREFIX/venv/bin/python -m centinela_central -c $CONF serve
Restart=always
RestartSec=5
UMask=0027
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$STATE
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
CapabilityBoundingSet=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

"$LAUNCHER" init
chmod 640 "$STATE"/central.db* 2>/dev/null || true
systemctl daemon-reload
systemctl enable centinela-central >/dev/null 2>&1
systemctl restart centinela-central

# Solo la seccion [server]: [smtp] tambien tiene «port».
SRV=$(sed -n '/^\[server\]/,/^\[/p' "$CONF")
PUB=$(printf '%s\n' "$SRV" | sed -n 's/^public_url = //p')
BP=$(printf '%s\n' "$SRV" | sed -n 's/^base_path = *//p')
P=$(printf '%s\n' "$SRV" | sed -n 's/^port = //p')
cat <<EOF

Centinela central en marcha en 127.0.0.1:$P. Falta publicarlo con HTTPS:

  nginx (dentro del server { } del dominio):
    location ^~ ${BP}/ {
        proxy_pass http://127.0.0.1:$P;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        client_max_body_size 10m;
    }

  Caddy:
    $(echo "$PUB" | sed -E 's|^https?://([^/]+).*|\1|') {
        reverse_proxy 127.0.0.1:$P
    }

Después entra en $PUB/ con el usuario admin.
Registro: journalctl -u centinela-central -f · Administración: centinela-central --help
EOF
