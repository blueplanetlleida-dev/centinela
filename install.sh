#!/usr/bin/env bash
#
# Centinela - instalador.
#
# Despliega un panel de seguridad en un subdominio, con un colector que corre
# como root por systemd, alertas por correo e informe semanal. Funciona en
# servidores con Plesk, con HestiaCP, o sin panel (Ubuntu/Debian/AlmaLinux con
# nginx o Apache y PHP-FPM instalados a mano).
#
#   ./install.sh --domain cyberseguridad.midominio.com --email admin@midominio.com
#
set -euo pipefail

VERSION="1.1.2"
PREFIX="/usr/local/centinela"
STATE_DIR="/var/lib/centinela"
CONFIG_DIR="/etc/centinela"
CONFIG_FILE="${CONFIG_DIR}/config.php"
GROUP="centinela"
INTERVAL="5min"
WATCH_INTERVAL="1min"
UPDATE_REPO=""
UPDATE_MODE="notify"
WEEKLY_SCHEDULE="Mon *-*-* 08:00:00"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DOMAIN=""
EMAIL=""
LG_PUBLIC="yes"
SKIP_SSL="no"
SKIP_DNS_CHECK="no"
ASSUME_YES="no"
UNINSTALL="no"
UPGRADE="no"
PLATFORM=""          # plesk | hestia | generic (vacio = detectar)
HESTIA_USER="admin"  # usuario de Hestia que aloja el panel
WEBSERVER=""         # sin panel: nginx | apache (vacio = detectar)
GENERIC_USER="centinela-web"
GENERIC_ROOT="/var/www/centinela"

# ------------------------------------------------------------------ salida --
if [[ -t 1 ]]; then
  B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'
else
  B=""; R=""; G=""; Y=""; C=""; N=""
fi
info()  { printf '%s\n' "  $*"; }
step()  { printf '\n%s\n' "${B}${C}==>${N} ${B}$*${N}"; }
ok()    { printf '%s\n' "  ${G}✓${N} $*"; }
warn()  { printf '%s\n' "  ${Y}!${N} $*"; }
die()   { printf '%s\n' "  ${R}✗${N} $*" >&2; exit 1; }

# Extrae un campo de la salida de «plesk bin <objeto> --info», tolerando que
# el binario termine con codigo distinto de cero.
plesk_field() {
  local kind="$1" name="$2" pattern="$3" out=""
  out="$($PLESK_BIN bin "$kind" --info "$name" 2>/dev/null || true)"
  printf '%s' "$out" | awk -F': +' -v pat="$pattern" '$0 ~ pat {print $2; exit}'
}

# Unidades de systemd que instala Centinela.
UNITS=(centinela-collect.service centinela-collect.timer
       centinela-weekly.service centinela-weekly.timer
       centinela-recheck.service centinela-recheck.path
       centinela-action.service centinela-action.path
       centinela-watch.service centinela-watch.timer
       centinela-update.service centinela-update.timer)

# Escribe las unidades sustituyendo las marcas de la plantilla. La usan tanto
# la instalacion como la actualizacion: si solo se copiara bin/ y lib/, un
# cambio en los ficheros de systemd nunca llegaria al servidor.
install_units() {
  local unit
  for unit in "${UNITS[@]}"; do
    [[ -f "$PREFIX/systemd/${unit}" ]] || continue
    sed -e "s|__PHP__|${PHP_BIN}|g" \
        -e "s|__PREFIX__|${PREFIX}|g" \
        -e "s|__STATE__|${STATE_DIR}|g" \
        -e "s|__GROUP__|${GROUP}|g" \
        -e "s|__INTERVAL__|${INTERVAL}|g" \
        -e "s|__WATCH_INTERVAL__|${WATCH_INTERVAL}|g" \
        -e "s|__SCHEDULE__|${WEEKLY_SCHEDULE}|g" \
        "$PREFIX/systemd/${unit}" > "/etc/systemd/system/${unit}"
  done
  systemctl daemon-reload
}

# Recarga todos los PHP-FPM en marcha: sin eso, opcache seguiria sirviendo el
# codigo anterior hasta un minuto, y el usuario web no heredaria el grupo nuevo.
reload_fpm() {
  local u any="no"
  for u in $(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
       | awk '{print $1}' | grep -E '^plesk-php[0-9]+-fpm\.service$|^php[0-9.]*-fpm\.service$'); do
    systemctl reload "$u" 2>/dev/null || systemctl restart "$u" 2>/dev/null || true
    any="yes"
  done
  [[ "$any" == "yes" ]]
}

# Jail de fail2ban que recibe los bloqueos manuales fuera de Plesk. Plesk trae
# plesk-permanent-ban; en los demas se crea uno propio, sin filtro (nadie
# escribe en el salvo el panel y la geo-valla) y con baneo permanente.
install_ban_jail() {
  [[ "$PLATFORM" != "plesk" ]] || return 0
  command -v fail2ban-client >/dev/null 2>&1 || { warn "fail2ban no esta instalado: el bloqueo desde el panel no funcionara hasta instalarlo"; return 0; }
  [[ -f /etc/fail2ban/jail.d/centinela.local ]] && return 0
  local action='%(banaction_allports)s[name=centinela]'
  [[ -f /etc/fail2ban/action.d/hestia.conf ]] && action='hestia[name=CENTINELA]'
  install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d
  cat > /etc/fail2ban/filter.d/centinela.conf <<'F2B'
# Generado por Centinela. Filtro vacio: en este jail solo entran las IPs que
# banea el panel o la geo-valla con «fail2ban-client set centinela banip».
[Definition]
failregex =
ignoreregex =
F2B
  cat > /etc/fail2ban/jail.d/centinela.local <<F2B
# Generado por Centinela: jail para los bloqueos hechos desde el panel.
[centinela]
enabled  = true
filter   = centinela
logpath  = /dev/null
maxretry = 1
findtime = 1d
bantime  = -1
action   = ${action}
F2B
  if systemctl is-active fail2ban >/dev/null 2>&1; then
    fail2ban-client reload >/dev/null 2>&1 && ok "Jail «centinela» creado en fail2ban" \
      || warn "fail2ban no recargo el jail «centinela»; revisa: fail2ban-client -d"
  else
    ok "Jail «centinela» preparado (fail2ban parado; se cargara al arrancar)"
  fi
}

usage() {
  cat <<EOF
${B}Centinela ${VERSION}${N} - panel de seguridad para servidores Plesk, HestiaCP o sin panel

Uso:
  ./install.sh --domain <subdominio> --email <admin@dominio> [opciones]

Obligatorio:
  --domain DOMINIO      Subdominio donde se publicara el panel
  --email  DIRECCION    Administrador que recibe alertas e informe semanal

Opciones:
  --platform TIPO       plesk | hestia | generic (por defecto se detecta)
  --hestia-user USUARIO Usuario de Hestia que alojara el panel (por defecto: ${HESTIA_USER})
  --webserver TIPO      Sin panel: nginx | apache (por defecto se detecta)
  --interval TIEMPO     Frecuencia de recogida (por defecto: ${INTERVAL})
  --weekly-day DIA      Dia del informe semanal: Mon..Sun (por defecto: Mon)
  --weekly-hour HORA    Hora del informe (por defecto: 08)
  --private-lg          El looking glass exige inicio de sesion
  --skip-ssl            No emitir certificado Let's Encrypt
  --skip-dns-check      No comprobar que el subdominio resuelve
  --update-repo REPO    Repositorio GitHub usuario/centinela para actualizarse solo
  --update-mode MODO    auto | patch | notify (por defecto: ${UPDATE_MODE})
  --prefix RUTA         Directorio de instalacion (por defecto: ${PREFIX})
  -y, --yes             No pedir confirmacion
  --upgrade             Actualiza los ficheros conservando la configuracion
  --uninstall           Desinstala Centinela
  -h, --help            Esta ayuda
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)         DOMAIN="${2:-}"; shift 2 ;;
    --email)          EMAIL="${2:-}"; shift 2 ;;
    --platform)       PLATFORM="${2:-}"; shift 2 ;;
    --hestia-user)    HESTIA_USER="${2:-admin}"; shift 2 ;;
    --webserver)      WEBSERVER="${2:-}"; shift 2 ;;
    --interval)       INTERVAL="${2:-}"; shift 2 ;;
    --watch-interval) WATCH_INTERVAL="${2:-}"; shift 2 ;;
    --update-repo)    UPDATE_REPO="${2:-}"; shift 2 ;;
    --update-mode)    UPDATE_MODE="${2:-notify}"; shift 2 ;;
    --weekly-day)     WEEKLY_DAY="${2:-Mon}"; shift 2 ;;
    --weekly-hour)    WEEKLY_HOUR="${2:-08}"; shift 2 ;;
    --private-lg)     LG_PUBLIC="no"; shift ;;
    --skip-ssl)       SKIP_SSL="yes"; shift ;;
    --skip-dns-check) SKIP_DNS_CHECK="yes"; shift ;;
    --prefix)         PREFIX="${2:-}"; shift 2 ;;
    -y|--yes)         ASSUME_YES="yes"; shift ;;
    --upgrade)        UPGRADE="yes"; shift ;;
    --uninstall)      UNINSTALL="yes"; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) die "Opcion desconocida: $1 (usa --help)" ;;
  esac
done

WEEKLY_SCHEDULE="${WEEKLY_DAY:-Mon} *-*-* ${WEEKLY_HOUR:-08}:00:00"

[[ $EUID -eq 0 ]] || die "Este instalador debe ejecutarse como root."

# ============================================================ desinstalar ===
if [[ "$UNINSTALL" == "yes" ]]; then
  step "Desinstalando Centinela"
  for u in "${UNITS[@]}"; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${u}"
  done
  systemctl daemon-reload
  ok "Temporizadores retirados"
  rm -rf "$PREFIX"; ok "Codigo eliminado de ${PREFIX}"
  for b in centinela-admin centinela-report centinela-collect centinela-watch centinela-action centinela-update; do
    rm -f "/usr/local/bin/${b}"
  done
  ok "Enlaces eliminados"
  # Lo que creo el instalador fuera de un panel
  for f in /etc/nginx/sites-enabled/centinela.conf /etc/nginx/sites-available/centinela.conf \
           /etc/nginx/conf.d/centinela.conf /etc/apache2/sites-enabled/centinela.conf \
           /etc/apache2/sites-available/centinela.conf /etc/httpd/conf.d/centinela.conf \
           /etc/php/*/fpm/pool.d/centinela.conf /etc/php-fpm.d/centinela.conf; do
    [[ -e "$f" ]] && grep -q 'Generado por Centinela' "$f" 2>/dev/null && rm -f "$f" && info "Retirado ${f}"
  done
  info ""
  info "Se conservan (borralos a mano si quieres):"
  info "  ${CONFIG_DIR}   configuracion y credenciales"
  info "  ${STATE_DIR}    historico de ataques y estado"
  info "  el subdominio del panel y sus ficheros"
  info "  /etc/fail2ban/jail.d/centinela.local, si existe"
  exit 0
fi

# ============================================================ validaciones ===
step "Comprobando el entorno"

PLESK_BIN=""
for p in /usr/sbin/plesk /usr/local/psa/bin/plesk /opt/psa/bin/plesk; do
  [[ -x "$p" ]] && { PLESK_BIN="$p"; break; }
done

# Plataforma: la que diga la configuracion existente, la del flag, o la detectada
if [[ -z "$PLATFORM" && -f "$CONFIG_FILE" ]]; then
  PLATFORM="$(awk -F"'" '/^[[:space:]]*'"'"'platform'"'"'[[:space:]]*=>/{print $4; exit}' "$CONFIG_FILE" 2>/dev/null || true)"
fi
if [[ -z "$PLATFORM" ]]; then
  if [[ -n "$PLESK_BIN" ]]; then PLATFORM="plesk"
  elif [[ -x /usr/local/hestia/bin/v-list-users ]]; then PLATFORM="hestia"
  else PLATFORM="generic"; fi
fi
case "$PLATFORM" in
  plesk)
    [[ -n "$PLESK_BIN" ]] || die "Se pidio --platform plesk pero no se ha encontrado Plesk."
    PLESK_VER="$({ $PLESK_BIN version 2>/dev/null || true; } | awk -F': +' '/Product version/{print $2}')"
    ok "Plataforma: Plesk ${PLESK_VER:-desconocido}" ;;
  hestia)
    [[ -x /usr/local/hestia/bin/v-list-users ]] || die "Se pidio --platform hestia pero no se ha encontrado HestiaCP."
    HESTIA_VER="$(awk -F"'" '/^VERSION=/{print $2}' /usr/local/hestia/conf/hestia.conf 2>/dev/null || true)"
    ok "Plataforma: HestiaCP ${HESTIA_VER:-desconocida}" ;;
  generic)
    ok "Plataforma: Linux sin panel" ;;
  *) die "Plataforma desconocida: ${PLATFORM} (plesk, hestia o generic)" ;;
esac

# Se lee en subshell: /etc/os-release define VERSION y pisaria la nuestra.
if [[ -f /etc/os-release ]]; then
  OS_PRETTY="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-desconocido}")"
  OS_ID="$(. /etc/os-release; printf '%s' "${ID:-}")"
  ok "Sistema: ${OS_PRETTY}"
fi

command -v systemctl >/dev/null || die "Se requiere systemd."

# PHP: en Plesk el suyo mas reciente; en el resto el del sistema
PHP_BIN=""
if [[ "$PLATFORM" == "plesk" ]]; then
  for v in 8.5 8.4 8.3 8.2 8.1; do
    if [[ -x "/opt/plesk/php/${v}/bin/php" ]]; then PHP_BIN="/opt/plesk/php/${v}/bin/php"; break; fi
  done
fi
[[ -n "$PHP_BIN" ]] || PHP_BIN="$(command -v php || true)"
if [[ -z "$PHP_BIN" ]]; then
  for v in 8.5 8.4 8.3 8.2 8.1; do
    if [[ -x "/usr/bin/php${v}" ]]; then PHP_BIN="/usr/bin/php${v}"; break; fi
  done
fi
[[ -n "$PHP_BIN" ]] || die "No se ha encontrado ningun interprete PHP. Instala php-cli y php-fpm (apt-get install php-cli php-fpm | dnf install php-cli php-fpm)."
PHP_VER="$($PHP_BIN -r 'echo PHP_VERSION;')"
PHP_MM="${PHP_VER%.*}"
[[ "$($PHP_BIN -r 'echo version_compare(PHP_VERSION,"8.1.0",">=") ? 1 : 0;')" == "1" ]] \
  || die "Se requiere PHP 8.1 o superior (encontrado ${PHP_VER})."
ok "PHP: ${PHP_BIN} (${PHP_VER})"

for ext in json openssl hash; do
  $PHP_BIN -m | grep -qi "^${ext}$" || die "Falta la extension PHP: ${ext}"
done
ok "Extensiones PHP necesarias presentes"

if [[ "$UPGRADE" != "yes" ]]; then
  [[ -n "$DOMAIN" ]] || die "Falta --domain. Ejemplo: --domain cyberseguridad.midominio.com"
  [[ -n "$EMAIL"  ]] || die "Falta --email. El informe semanal al administrador es obligatorio."
  [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]] \
    || die "El dominio no tiene un formato valido: ${DOMAIN}"
  [[ "$EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[a-zA-Z]{2,}$ ]] \
    || die "La direccion de correo no es valida: ${EMAIL}"
fi

# Sin panel hace falta un servidor web y un PHP-FPM que sirvan la interfaz
if [[ "$PLATFORM" == "generic" && "$UPGRADE" != "yes" ]]; then
  if [[ -z "$WEBSERVER" ]]; then
    if systemctl is-active nginx >/dev/null 2>&1; then WEBSERVER="nginx"
    elif systemctl is-active apache2 >/dev/null 2>&1 || systemctl is-active httpd >/dev/null 2>&1; then WEBSERVER="apache"
    elif command -v nginx >/dev/null 2>&1; then WEBSERVER="nginx"
    elif command -v apache2ctl >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then WEBSERVER="apache"
    fi
  fi
  [[ "$WEBSERVER" == "nginx" || "$WEBSERVER" == "apache" ]] \
    || die "No hay nginx ni Apache. Instala uno (apt-get install nginx php${PHP_MM}-fpm) y repite."
  if [[ -x "/usr/sbin/php-fpm${PHP_MM}" && -d "/etc/php/${PHP_MM}/fpm/pool.d" ]]; then
    FPM_SVC="php${PHP_MM}-fpm"; FPM_POOL_DIR="/etc/php/${PHP_MM}/fpm/pool.d"; FPM_SOCK="/run/php/centinela.sock"
  elif [[ -x /usr/sbin/php-fpm && -d /etc/php-fpm.d ]]; then
    FPM_SVC="php-fpm"; FPM_POOL_DIR="/etc/php-fpm.d"; FPM_SOCK="/run/php-fpm/centinela.sock"
  else
    die "No se ha encontrado PHP-FPM para PHP ${PHP_MM}. Instalalo (apt-get install php${PHP_MM}-fpm | dnf install php-fpm) y repite."
  fi
  ok "Servidor web: ${WEBSERVER}; PHP-FPM: ${FPM_SVC}"
fi

# ================================================================ upgrade ===
if [[ "$UPGRADE" == "yes" ]]; then
  [[ -d "$PREFIX" ]] || die "No hay instalacion previa en ${PREFIX}"
  step "Actualizando ficheros de Centinela"
  install -d -m 0755 "$PREFIX"
  cp -a "$SRC/bin" "$SRC/lib" "$SRC/systemd" "$PREFIX/"
  chmod 0755 "$PREFIX"/bin/*
  cp -a "$SRC/lib/config.php" "$PREFIX/lib/config.php"
  ok "Codigo actualizado"

  # Conservamos la periodicidad que ya estuviera configurada: al actualizar no
  # tiene por que volver a los valores por defecto.
  INSTALLED_INTERVAL="$(awk -F= '/^OnUnitActiveSec=/{print $2; exit}' \
    /etc/systemd/system/centinela-collect.timer 2>/dev/null || true)"
  INSTALLED_SCHEDULE="$(awk -F= '/^OnCalendar=/{print $2; exit}' \
    /etc/systemd/system/centinela-weekly.timer 2>/dev/null || true)"
  INSTALLED_WATCH="$(awk -F= '/^OnUnitActiveSec=/{print $2; exit}' \
    /etc/systemd/system/centinela-watch.timer 2>/dev/null || true)"
  [[ -n "$INSTALLED_INTERVAL" ]] && INTERVAL="$INSTALLED_INTERVAL"
  [[ -n "$INSTALLED_SCHEDULE" ]] && WEEKLY_SCHEDULE="$INSTALLED_SCHEDULE"
  [[ -n "$INSTALLED_WATCH" ]] && WATCH_INTERVAL="$INSTALLED_WATCH"
  install_units
  ok "Unidades de systemd actualizadas"
  DOCROOT="$(cat "${CONFIG_DIR}/.docroot" 2>/dev/null || true)"
  if [[ -n "$DOCROOT" && -d "$DOCROOT" ]]; then
    WEBOWNER="$(stat -c '%U:%G' "$DOCROOT")"
    cp -a "$SRC/web/." "$DOCROOT/"
    cp -a "$SRC/lib/config.php" "$SRC/lib/totp.php" "$DOCROOT/lib/"
    chown -R "$WEBOWNER" "$DOCROOT"
    ok "Interfaz web actualizada en ${DOCROOT}"
    # La cola de recomprobaciones puede no existir si la instalacion es anterior
    # a esa funcion; la creamos con los mismos permisos que el resto.
    install -d -m 2770 -o "$(stat -c '%U' "$DOCROOT")" -g "$GROUP" "$STATE_DIR/queue"
    install -d -m 2770 -o "$(stat -c '%U' "$DOCROOT")" -g "$GROUP" "$STATE_DIR/queue/actions"
    # Progreso de las correcciones largas. Al reves que la cola: lo escribe root
    # y la web solo lee, asi que no lleva setgid ni permiso de escritura.
    install -d -m 0750 -o root -g "$GROUP" "$STATE_DIR/jobs"
  else
    warn "No se pudo determinar el docroot; copia web/ manualmente"
  fi
  install_ban_jail
  systemctl restart centinela-collect.timer 2>/dev/null || true
  for u in centinela-watch.timer centinela-update.timer centinela-recheck.path centinela-action.path; do
    systemctl enable --now "$u" >/dev/null 2>&1 || warn "No se pudo activar ${u}"
  done
  reload_fpm && ok "PHP recargado" || warn "No se encontro ningun PHP-FPM que recargar"
  ok "Actualizacion completada"
  exit 0
fi

# ============================================================== resumen ====
case "$PLATFORM" in
  plesk)   DONDE="subdominio de Plesk" ;;
  hestia)  DONDE="dominio de Hestia (usuario ${HESTIA_USER})" ;;
  generic) DONDE="vhost de ${WEBSERVER} en ${GENERIC_ROOT}" ;;
esac
cat <<EOF

${B}Se va a instalar Centinela ${VERSION}${N}

  Subdominio      ${C}${DOMAIN}${N}  (${DONDE})
  Administrador   ${C}${EMAIL}${N}
  Codigo          ${PREFIX}
  Configuracion   ${CONFIG_FILE}
  Datos           ${STATE_DIR}
  Recogida cada   ${INTERVAL}
  Informe semanal ${WEEKLY_SCHEDULE}
  Looking glass   $([[ "$LG_PUBLIC" == "yes" ]] && echo "publico en /lg.php" || echo "privado")
  Certificado     $([[ "$SKIP_SSL" == "yes" ]] && echo "no se emite" || echo "Let's Encrypt")

EOF

if [[ "$ASSUME_YES" != "yes" ]]; then
  read -r -p "  ¿Continuar? [s/N] " answer
  [[ "$answer" =~ ^[sSyY]$ ]] || { info "Cancelado."; exit 0; }
fi

# ========================================================= dns (aviso) =====
if [[ "$SKIP_DNS_CHECK" != "yes" ]]; then
  step "Comprobando el DNS de ${DOMAIN}"
  RESOLVED="$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1 || true)"
  if [[ -z "$RESOLVED" ]]; then
    warn "${DOMAIN} no resuelve todavia."
    warn "Crea el registro A apuntando a este servidor antes de emitir el certificado."
    SKIP_SSL="yes"
  else
    ok "Resuelve a ${RESOLVED}"
  fi
fi

PARENT="${DOMAIN#*.}"
SUBNAME="${DOMAIN%%.*}"

# =========================================================== sitio web =====
case "$PLATFORM" in

# ------------------------------------------------------ subdominio Plesk ---
plesk)
  step "Preparando el subdominio en Plesk"
  if $PLESK_BIN bin domain --info "$DOMAIN" >/dev/null 2>&1 || \
     $PLESK_BIN bin subdomain --info "$DOMAIN" >/dev/null 2>&1; then
    ok "El dominio ${DOMAIN} ya existe en Plesk"
  else
    if ! $PLESK_BIN bin domain --info "$PARENT" >/dev/null 2>&1; then
      die "El dominio padre ${PARENT} no existe en Plesk. Crealo primero."
    fi
    info "Creando subdominio ${SUBNAME} bajo ${PARENT}..."
    # -www-root evita que Plesk genere un directorio con nombre automatico
    $PLESK_BIN bin subdomain --create "$SUBNAME" -domain "$PARENT" -www-root "$SUBNAME" \
      || die "No se pudo crear el subdominio. Crealo desde el panel y repite con el mismo --domain."
    ok "Subdominio creado"
  fi

  # Localizamos el docroot y el usuario del sistema que sirve el dominio.
  # Las utilidades de Plesk devuelven codigos distintos de cero aunque impriman
  # la informacion correctamente, asi que no dejamos que aborten la instalacion.
  DOCROOT="$(plesk_field subdomain "$DOMAIN" 'WWW-Root|Document root')"
  [[ -n "$DOCROOT" ]] || DOCROOT="$(plesk_field domain "$DOMAIN" 'WWW-Root|Document root')"
  if [[ -z "$DOCROOT" || ! -d "$DOCROOT" ]]; then
    GUESS="/var/www/vhosts/${PARENT}/${SUBNAME}"
    [[ -d "$GUESS" ]] && DOCROOT="$GUESS"
  fi
  [[ -n "$DOCROOT" && -d "$DOCROOT" ]] || die "No se ha podido localizar el directorio del subdominio."
  WEBUSER="$(stat -c '%U' "$DOCROOT")"
  # Plesk sirve el contenido con el grupo psacln; si no existe usamos el del vhost.
  if getent group psacln >/dev/null; then WEBGROUP="psacln"; else WEBGROUP="$(stat -c '%G' "$DOCROOT")"; fi
  ;;

# --------------------------------------------------------- dominio Hestia --
hestia)
  step "Preparando el dominio en HestiaCP"
  HB=/usr/local/hestia/bin
  "$HB/v-list-user" "$HESTIA_USER" >/dev/null 2>&1 || die "El usuario de Hestia «${HESTIA_USER}» no existe (usa --hestia-user)."
  if "$HB/v-list-web-domain" "$HESTIA_USER" "$DOMAIN" >/dev/null 2>&1; then
    ok "El dominio ${DOMAIN} ya existe en Hestia"
  else
    info "Creando ${DOMAIN} para el usuario ${HESTIA_USER}..."
    "$HB/v-add-web-domain" "$HESTIA_USER" "$DOMAIN" \
      || die "No se pudo crear el dominio. Crealo desde Hestia y repite con el mismo --domain."
    ok "Dominio creado"
  fi
  DOCROOT="/home/${HESTIA_USER}/web/${DOMAIN}/public_html"
  [[ -d "$DOCROOT" ]] || die "No existe ${DOCROOT}; revisa el dominio en Hestia."
  WEBUSER="$HESTIA_USER"
  WEBGROUP="$(stat -c '%G' "$DOCROOT")"
  ;;

# ------------------------------------------------------------ sin panel ----
generic)
  step "Creando el sitio del panel (${WEBSERVER} + ${FPM_SVC})"
  if ! getent passwd "$GENERIC_USER" >/dev/null; then
    useradd --system --home-dir "$GENERIC_ROOT" --shell /usr/sbin/nologin --user-group "$GENERIC_USER" 2>/dev/null \
      || useradd --system --home-dir "$GENERIC_ROOT" --shell /sbin/nologin "$GENERIC_USER"
    ok "Usuario de sistema ${GENERIC_USER} creado"
  fi
  DOCROOT="${GENERIC_ROOT}/public"
  install -d -m 0755 -o "$GENERIC_USER" -g "$GENERIC_USER" "$GENERIC_ROOT" "$DOCROOT"
  WEBUSER="$GENERIC_USER"
  WEBGROUP="$GENERIC_USER"

  # Usuario con el que corre el servidor web, dueno del socket del pool
  if getent passwd www-data >/dev/null; then WEB_RUN_USER="www-data"
  elif [[ "$WEBSERVER" == "nginx" ]] && getent passwd nginx >/dev/null; then WEB_RUN_USER="nginx"
  elif getent passwd apache >/dev/null; then WEB_RUN_USER="apache"
  else WEB_RUN_USER="$GENERIC_USER"; fi

  # Pool PHP-FPM propio: corre como el usuario del panel y con open_basedir
  # limitado a lo que necesita leer.
  cat > "${FPM_POOL_DIR}/centinela.conf" <<POOL
; Generado por Centinela. Pool del panel de seguridad.
[centinela]
user = ${GENERIC_USER}
group = ${GENERIC_USER}
listen = ${FPM_SOCK}
listen.owner = ${WEB_RUN_USER}
listen.group = ${WEB_RUN_USER}
listen.mode = 0660
pm = ondemand
pm.max_children = 6
pm.process_idle_timeout = 30s
php_admin_value[open_basedir] = ${DOCROOT}:${CONFIG_DIR}:${STATE_DIR}:/tmp:/usr/bin:/bin
php_admin_value[disable_functions] =
php_admin_flag[expose_php] = off
php_value[session.save_path] = ${STATE_DIR}/sessions
POOL
  systemctl enable "$FPM_SVC" >/dev/null 2>&1 || true
  systemctl restart "$FPM_SVC" || die "PHP-FPM (${FPM_SVC}) no arranca con el pool nuevo; revisa: journalctl -u ${FPM_SVC}"
  ok "Pool PHP-FPM «centinela» en ${FPM_SOCK}"

  if [[ "$WEBSERVER" == "nginx" ]]; then
    if [[ -d /etc/nginx/sites-available ]]; then NGX_CONF=/etc/nginx/sites-available/centinela.conf
    else NGX_CONF=/etc/nginx/conf.d/centinela.conf; fi
    cat > "$NGX_CONF" <<NGX
# Generado por Centinela. Panel de seguridad en ${DOMAIN}.
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root ${DOCROOT};
    index index.php;
    access_log /var/log/nginx/centinela.access.log;
    error_log  /var/log/nginx/centinela.error.log;

    # Nada de lo que hay en lib/ ni ningun fichero oculto se sirve
    location ~ ^/lib/ { deny all; }
    location ~ /\.(?!well-known) { deny all; }

    # El panel refleja el estado del servidor: nunca se cachea, ni el CSS
    location ~* \.(css|js)$ { add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0"; }

    location / { try_files \$uri \$uri/ =404; }
    location ~ \.php$ {
        try_files \$uri =404;
        include fastcgi_params;
        fastcgi_pass unix:${FPM_SOCK};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_read_timeout 60s;
    }
}
NGX
    [[ -d /etc/nginx/sites-enabled ]] && ln -sfn "$NGX_CONF" /etc/nginx/sites-enabled/centinela.conf
    nginx -t >/dev/null 2>&1 || die "La configuracion de nginx no valida; revisa: nginx -t"
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
    ok "Sitio nginx publicado (${NGX_CONF})"
  else
    if command -v a2enmod >/dev/null 2>&1; then
      APACHE_SVC=apache2; AP_CONF=/etc/apache2/sites-available/centinela.conf; AP_LOGDIR='${APACHE_LOG_DIR}'
      a2enmod proxy_fcgi setenvif rewrite headers >/dev/null 2>&1 || true
    else
      APACHE_SVC=httpd; AP_CONF=/etc/httpd/conf.d/centinela.conf; AP_LOGDIR='/var/log/httpd'
    fi
    cat > "$AP_CONF" <<APA
# Generado por Centinela. Panel de seguridad en ${DOMAIN}.
<VirtualHost *:80>
    ServerName ${DOMAIN}
    DocumentRoot ${DOCROOT}
    ErrorLog ${AP_LOGDIR}/centinela.error.log
    CustomLog ${AP_LOGDIR}/centinela.access.log combined
    <Directory ${DOCROOT}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    <Directory ${DOCROOT}/lib>
        Require all denied
    </Directory>
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:${FPM_SOCK}|fcgi://localhost/"
    </FilesMatch>
</VirtualHost>
APA
    [[ "$APACHE_SVC" == "apache2" ]] && a2ensite centinela.conf >/dev/null 2>&1
    { apache2ctl -t >/dev/null 2>&1 || httpd -t >/dev/null 2>&1; } || die "La configuracion de Apache no valida; revisa: apache2ctl -t"
    systemctl enable "$APACHE_SVC" >/dev/null 2>&1 || true
    systemctl reload "$APACHE_SVC" 2>/dev/null || systemctl restart "$APACHE_SVC"
    ok "Sitio Apache publicado (${AP_CONF})"
  fi
  ;;
esac
ok "Docroot: ${DOCROOT} (usuario ${WEBUSER}, grupo ${WEBGROUP})"

# =========================================================== instalacion ===
step "Instalando el codigo"

# El codigo que corre como root vive fuera del vhost y pertenece a root:
# si un sitio alojado se viera comprometido, no podria alterarlo.
install -d -m 0755 "$PREFIX"
cp -a "$SRC/bin" "$SRC/lib" "$SRC/systemd" "$PREFIX/"
chown -R root:root "$PREFIX"
chmod 0755 "$PREFIX"/bin/*
ok "Codigo privilegiado en ${PREFIX} (propiedad de root)"

# Grupo dedicado para compartir el estado con el usuario web
if ! getent group "$GROUP" >/dev/null; then
  groupadd --system "$GROUP"
  ok "Grupo ${GROUP} creado"
fi
usermod -a -G "$GROUP" "$WEBUSER" 2>/dev/null || warn "No se pudo anadir ${WEBUSER} al grupo ${GROUP}"

install -d -m 0750 -o root -g "$GROUP" "$STATE_DIR"
install -d -m 0750 -o root -g "$GROUP" "$STATE_DIR/cache"
# Estos los escribe la web, no el colector
install -d -m 2770 -o "$WEBUSER" -g "$GROUP" "$STATE_DIR/sessions"
install -d -m 2770 -o "$WEBUSER" -g "$GROUP" "$STATE_DIR/rl"
install -d -m 2770 -o "$WEBUSER" -g "$GROUP" "$STATE_DIR/webcache"
# Cola de peticiones: aqui deja la web la senal de «volver a comprobar» que
# recoge centinela-recheck.path. Es lo unico que puede pedir trabajo con
# privilegios, y su contenido no decide que se ejecuta.
install -d -m 2770 -o "$WEBUSER" -g "$GROUP" "$STATE_DIR/queue"
# Y dentro, las acciones sobre IPs: van a su propio directorio porque systemd
# lo vigila con DirectoryNotEmpty.
install -d -m 2770 -o "$WEBUSER" -g "$GROUP" "$STATE_DIR/queue/actions"
# Progreso de las correcciones largas. Al reves que la cola: lo escribe root y
# la web solo lee, asi que no lleva setgid ni permiso de escritura para el web.
install -d -m 0750 -o root -g "$GROUP" "$STATE_DIR/jobs"
# La clave de firma del captcha la lee la web pero no puede crearla ahi:
# la generamos nosotros con permisos de solo lectura para el grupo.
if [[ ! -f "$STATE_DIR/captcha.key" ]]; then
  "$PHP_BIN" -r 'echo bin2hex(random_bytes(32));' > "$STATE_DIR/captcha.key"
  chown root:"$GROUP" "$STATE_DIR/captcha.key"
  chmod 0640 "$STATE_DIR/captcha.key"
fi
# El registro de accesos lo escribe la web
touch "$STATE_DIR/access.log"
chown "$WEBUSER":"$GROUP" "$STATE_DIR/access.log"
chmod 0660 "$STATE_DIR/access.log"
ok "Directorio de datos en ${STATE_DIR}"

# Interfaz web en el docroot, propiedad del usuario del dominio
step "Desplegando la interfaz web"
find "$DOCROOT" -maxdepth 1 -name 'index.html' -delete 2>/dev/null || true
cp -a "$SRC/web/." "$DOCROOT/"
# Componentes compartidos con el colector: se copian junto a la web para que
# el docroot sea autonomo y no dependa de rutas fuera del vhost.
cp -a "$SRC/lib/config.php" "$SRC/lib/totp.php" "$DOCROOT/lib/"
chown -R "${WEBUSER}:${WEBGROUP}" "$DOCROOT"
find "$DOCROOT" -type f -exec chmod 0644 {} \;
find "$DOCROOT" -type d -exec chmod 0755 {} \;

# Los ficheros de lib solo definen funciones, pero los tapamos igualmente
cat > "$DOCROOT/lib/.htaccess" <<'HT'
Require all denied
HT
chown "${WEBUSER}:${WEBGROUP}" "$DOCROOT/lib/.htaccess"
ok "Interfaz publicada en ${DOCROOT}"

# ====================================================== open_basedir =======
# Los paneles restringen cada dominio a su propio espacio web. Sin ampliarlo,
# la interfaz no puede leer ni la configuracion ni los datos del colector.
case "$PLATFORM" in
plesk)
  step "Ampliando open_basedir del dominio"
  OB_FILE="$(mktemp)"
  printf 'open_basedir = {WEBSPACEROOT}{/}{:}{TMP}{/}{:}%s{:}%s\n' "$CONFIG_DIR" "$STATE_DIR" > "$OB_FILE"
  if $PLESK_BIN bin site --update-php-settings "$DOMAIN" -settings "$OB_FILE" >/dev/null 2>&1; then
    ok "El dominio puede leer ${CONFIG_DIR} y ${STATE_DIR}"
  else
    warn "No se pudo ampliar open_basedir automaticamente."
    warn "Hazlo en Plesk > ${DOMAIN} > PHP > open_basedir, anadiendo:"
    warn "  {WEBSPACEROOT}{/}{:}{TMP}{/}{:}${CONFIG_DIR}{:}${STATE_DIR}"
  fi
  rm -f "$OB_FILE"
  ;;
hestia)
  step "Ampliando open_basedir del dominio"
  # Hestia fija open_basedir en la plantilla PHP-FPM del dominio. Se deriva
  # una plantilla propia a partir de la actual y se asigna al dominio.
  HB=/usr/local/hestia/bin
  TPL_DIR=/usr/local/hestia/data/templates/web/php-fpm
  CUR_TPL="$("$HB/v-list-web-domain" "$HESTIA_USER" "$DOMAIN" json 2>/dev/null \
    | "$PHP_BIN" -r '$d=json_decode(stream_get_contents(STDIN),true); echo (string)(reset($d)["BACKEND"] ?? "");' 2>/dev/null || true)"
  [[ -n "$CUR_TPL" && -f "${TPL_DIR}/${CUR_TPL}.tpl" ]] || CUR_TPL="$(ls "$TPL_DIR" 2>/dev/null | grep -E '^PHP-[0-9]+_[0-9]+\.tpl$' | sort -V | tail -1 | sed 's/\.tpl$//')"
  if [[ -n "$CUR_TPL" && -f "${TPL_DIR}/${CUR_TPL}.tpl" ]]; then
    NEW_TPL="centinela-${CUR_TPL}"
    if grep -q 'open_basedir' "${TPL_DIR}/${CUR_TPL}.tpl"; then
      sed -E "s#^(\s*php_admin_value\[open_basedir\]\s*=\s*)(.*)\$#\1\2:${CONFIG_DIR}:${STATE_DIR}#" \
        "${TPL_DIR}/${CUR_TPL}.tpl" > "${TPL_DIR}/${NEW_TPL}.tpl"
    else
      cp "${TPL_DIR}/${CUR_TPL}.tpl" "${TPL_DIR}/${NEW_TPL}.tpl"
    fi
    if "$HB/v-change-web-domain-backend-tpl" "$HESTIA_USER" "$DOMAIN" "$NEW_TPL" >/dev/null 2>&1; then
      ok "Plantilla PHP-FPM «${NEW_TPL}» asignada: el dominio puede leer ${CONFIG_DIR} y ${STATE_DIR}"
    else
      warn "No se pudo asignar la plantilla PHP-FPM «${NEW_TPL}»."
      warn "Hazlo en Hestia > Web > ${DOMAIN} > Plantilla de backend, o anade a open_basedir: ${CONFIG_DIR}:${STATE_DIR}"
    fi
  else
    warn "No se encontro la plantilla PHP-FPM del dominio; si el panel no arranca, anade a open_basedir: ${CONFIG_DIR}:${STATE_DIR}"
  fi
  ;;
generic)
  : # ya viene en el pool
  ;;
esac

# =========================================================== configuracion ==
step "Generando la configuracion"
install -d -m 0750 -o root -g "$GROUP" "$CONFIG_DIR"
echo "$DOCROOT" > "${CONFIG_DIR}/.docroot"
chmod 0640 "${CONFIG_DIR}/.docroot"

case "$PLATFORM" in
  plesk) BAN_JAIL="plesk-permanent-ban" ;;
  *)     BAN_JAIL="centinela" ;;
esac

if [[ -f "$CONFIG_FILE" ]]; then
  warn "Ya existe ${CONFIG_FILE}; se conserva"
else
  TOTP_SECRET="$("$PHP_BIN" -r 'require $argv[1]; echo totp_secret();' "$SRC/lib/totp.php")"
  [[ -n "$TOTP_SECRET" ]] || die "No se pudo generar el secreto TOTP."

  cat > "$CONFIG_FILE" <<EOF
<?php
/**
 * Centinela - configuracion.
 * Generada por el instalador el $(date '+%d/%m/%Y %H:%M').
 * Contiene credenciales: mantener con permisos 0640.
 */

return [
    'timezone'  => '$(timedatectl show -p Timezone --value 2>/dev/null || echo Europe/Madrid)',
    'state_dir' => '${STATE_DIR}',

    // Plataforma detectada al instalar: plesk | hestia | generic.
    'platform'  => '${PLATFORM}',

    'auth' => [
        'user'          => 'admin',
        'hash'          => '',
        'totp_secret'   => '${TOTP_SECRET}',
        'totp_required' => true,
        'session_ttl'   => 7200,
        'max_attempts'  => 5,
        'lockout'       => 900,
    ],

    // Vacia: el filtrado por IP se hace en el cortafuegos de red.
    'ip_allowlist' => [],

    // Actualizacion automatica desde GitHub. Deja 'repo' vacio para
    // desactivarla; ponlo a 'usuario/centinela' cuando publiques el repo.
    'update' => [
        'repo'        => '${UPDATE_REPO}',
        // 'auto' aplica cualquier version nueva; 'patch' solo las de parche
        // (1.0.x); 'notify' solo avisa en el panel y no aplica nada.
        'mode'        => '${UPDATE_MODE}',
        'prereleases' => false,
    ],

    // Acciones que el panel puede pedir sobre una IP atacante.
    'actions' => [
        // Jail de fail2ban donde caen los bloqueos hechos desde el panel.
        'jail'      => '${BAN_JAIL}',
        // Direcciones o rangos que nunca se bloquean, pase lo que pase. Las redes
        // del propio servidor y la lista de confianza de arriba ya estan cubiertas.
        'never_ban' => [],
    ],

    // Rangos de proxy de confianza para leer la IP real del visitante.
    'trusted_proxies' => [],

    // Sin panel: si tus logs web o certificados no estan en los sitios
    // habituales, indica aqui los patrones (glob).
    'web'   => ['logs'  => []],
    'certs' => ['paths' => []],

    'mail' => [
        'enabled'        => true,
        'to'             => ['${EMAIL}'],
        'from'           => 'centinela@${PARENT}',
        'from_name'      => 'Centinela',
        'weekly'         => true,
        'alerts'         => true,
        'alert_min_sev'  => 'warn',
        'alert_throttle' => 86400,
        // Lo critico se reavisa antes: es lo que justifica levantarse a mirarlo.
        'alert_throttle_crit' => 3600,
    ],

    'lg' => [
        'enabled'    => true,
        'public'     => $([[ "$LG_PUBLIC" == "yes" ]] && echo 'true' || echo 'false'),
        'per_minute' => 10,
        'per_hour'   => 60,
        // Rutas detectadas durante la instalacion: el dominio tiene
        // open_basedir y no puede localizarlas por si mismo.
        'bin'        => [
$(for t in ping mtr traceroute dig host; do
    pth="$(command -v "$t" 2>/dev/null || true)"
    [[ -n "$pth" ]] && printf "            '%s' => '%s',\n" "$t" "$pth"
  done)
        ],
    ],
];
EOF
  chown root:"$GROUP" "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
  ok "Configuracion creada en ${CONFIG_FILE}"
fi

# ================================================================ fail2ban ==
if [[ "$PLATFORM" != "plesk" ]]; then
  step "Preparando el jail de bloqueos manuales"
  install_ban_jail
fi

# ================================================================ systemd ===
step "Instalando los temporizadores"
install_units
systemctl enable --now centinela-collect.timer >/dev/null
systemctl enable --now centinela-weekly.timer >/dev/null
systemctl enable --now centinela-recheck.path >/dev/null
systemctl enable --now centinela-action.path >/dev/null
systemctl enable --now centinela-watch.timer >/dev/null
systemctl enable --now centinela-update.timer >/dev/null
ok "centinela-collect.timer cada ${INTERVAL}"
ok "centinela-weekly.timer el ${WEEKLY_SCHEDULE}"

# Atajos en el PATH. Se generan como envoltorios y no como enlaces porque
# muchos servidores Plesk no tienen ningun «php» en el PATH del sistema:
# el interprete que usamos es el de Plesk y hay que invocarlo por ruta.
for b in centinela-admin centinela-report centinela-collect centinela-watch centinela-action centinela-update; do
  cat > "/usr/local/bin/${b}" <<WRAPPER
#!/bin/sh
# Envoltorio generado por el instalador de Centinela.
exec "${PHP_BIN}" "${PREFIX}/bin/${b}" "\$@"
WRAPPER
  chmod 0755 "/usr/local/bin/${b}"
done
ok "Comandos disponibles: centinela-admin, centinela-report"

# El proceso PHP del dominio solo hereda el grupo nuevo al reiniciarse.
step "Recargando PHP para aplicar la pertenencia al grupo"
FPM_RESTARTED="no"
for u in $(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
     | awk '{print $1}' | grep -E '^plesk-php[0-9]+-fpm\.service$|^php[0-9.]*-fpm\.service$'); do
  systemctl restart "$u" 2>/dev/null && { ok "Reiniciado ${u}"; FPM_RESTARTED="yes"; }
done
[[ "$FPM_RESTARTED" == "yes" ]] || warn "Reinicia PHP-FPM a mano para que ${WEBUSER} herede el grupo ${GROUP}"

# ============================================================ primera pasada =
step "Ejecutando la primera recogida"
if "$PHP_BIN" "$PREFIX/bin/centinela-collect" --quiet --state "$STATE_DIR" --group "$GROUP"; then
  ok "Estado inicial generado"
else
  warn "La primera recogida devolvio errores; revisa: journalctl -u centinela-collect"
fi

# ================================================================= SSL =====
if [[ "$SKIP_SSL" != "yes" ]]; then
  step "Emitiendo certificado Let's Encrypt"
  case "$PLATFORM" in
  plesk)
    if { $PLESK_BIN bin extension --list 2>/dev/null || true; } | grep -q '^letsencrypt'; then
      if $PLESK_BIN bin extension --exec letsencrypt cli.php -d "$DOMAIN" -m "$EMAIL" >/dev/null 2>&1; then
        ok "Certificado emitido para ${DOMAIN}"
      else
        warn "No se pudo emitir el certificado automaticamente."
        warn "Hazlo desde Plesk > ${DOMAIN} > Certificados SSL/TLS."
      fi
    else
      warn "La extension Let's Encrypt no esta instalada."
    fi ;;
  hestia)
    if /usr/local/hestia/bin/v-add-letsencrypt-domain "$HESTIA_USER" "$DOMAIN" >/dev/null 2>&1; then
      /usr/local/hestia/bin/v-add-web-domain-ssl-force "$HESTIA_USER" "$DOMAIN" >/dev/null 2>&1 || true
      ok "Certificado emitido para ${DOMAIN}"
    else
      warn "No se pudo emitir el certificado automaticamente."
      warn "Hazlo desde Hestia > Web > ${DOMAIN} > SSL, o: v-add-letsencrypt-domain ${HESTIA_USER} ${DOMAIN}"
    fi ;;
  generic)
    if command -v certbot >/dev/null 2>&1; then
      CB_PLUGIN="--nginx"; [[ "$WEBSERVER" == "apache" ]] && CB_PLUGIN="--apache"
      if certbot "$CB_PLUGIN" -d "$DOMAIN" -m "$EMAIL" --agree-tos --no-eff-email -n --redirect >/dev/null 2>&1; then
        ok "Certificado emitido para ${DOMAIN}"
      else
        warn "certbot no pudo emitir el certificado; revisa /var/log/letsencrypt/letsencrypt.log"
        warn "Repite a mano: certbot ${CB_PLUGIN} -d ${DOMAIN} -m ${EMAIL} --agree-tos --redirect"
      fi
    else
      warn "certbot no esta instalado (apt-get install certbot python3-certbot-${WEBSERVER}); el panel queda en http."
    fi ;;
  esac
fi

# ============================================================ credenciales ==
step "Credenciales de acceso"
info "Define ahora la contrasena del panel."
info ""
"$PHP_BIN" "$PREFIX/bin/centinela-admin" passwd admin || warn "Puedes definirla luego con: centinela-admin passwd"

echo
"$PHP_BIN" "$PREFIX/bin/centinela-admin" totp || true

# ================================================================= final ====
step "Instalacion completada"
cat <<EOF

  ${B}Panel${N}          https://${DOMAIN}/
  ${B}Looking glass${N}  https://${DOMAIN}/lg.php
  ${B}Usuario${N}        admin

  ${B}Comandos utiles${N}
    centinela-admin check          diagnostico de la instalacion
    centinela-admin show           configuracion vigente
    centinela-admin passwd         cambiar la contrasena
    centinela-admin totp --new     regenerar el segundo factor
    centinela-admin test-mail      probar el envio de correo
    centinela-admin update --repo USUARIO/centinela --mode auto   actualizarse solo desde GitHub
    centinela-report --weekly      enviar el informe semanal ahora
    journalctl -u centinela-collect -f    seguir el colector

  ${Y}Antes de terminar${N}
    1. Escanea el codigo QR con tu aplicacion de autenticacion.
    2. Comprueba la entrega de correo:  centinela-admin test-mail
    3. El panel no filtra por IP: restringe el acceso en tu cortafuegos.

EOF
