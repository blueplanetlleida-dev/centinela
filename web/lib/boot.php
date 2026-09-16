<?php
/**
 * Centinela - arranque comun de la capa web.
 *
 * Esta capa corre como el usuario del dominio, nunca como root. Solo lee
 * el JSON que genera el colector; no ejecuta nada privilegiado. La unica
 * ejecucion de comandos vive en el looking glass, con lista blanca estricta.
 */

declare(strict_types=1);

define('CENT_WEB', true);
$CENT_BASE = dirname(__DIR__, 2);

/*
 * El cargador de configuracion se comparte con el colector. En la instalacion
 * definitiva la web vive en el docroot del dominio y el codigo privilegiado en
 * /usr/local/centinela, de modo que buscamos en varios sitios: primero la copia
 * local que deja el instalador, luego el arbol de desarrollo.
 */
$centResolve = function (string $name) use ($CENT_BASE): string {
    foreach ([__DIR__ . '/' . $name, $CENT_BASE . '/lib/' . $name, '/usr/local/centinela/lib/' . $name] as $candidate) {
        if (is_readable($candidate)) {
            return $candidate;
        }
    }
    http_response_code(500);
    exit('Centinela: falta el componente ' . $name);
};

require $centResolve('config.php');
require $centResolve('totp.php');
require __DIR__ . '/ratelimit.php';

if (!defined('CENT_VERSION')) {
    define('CENT_VERSION', '1.1.2');
}

$CFG = load_config();

// -------------------------------------------------------------- cabeceras --
function send_security_headers(bool $allowInlineStyle = true): void
{
    // Sin recursos externos: todo va embebido, asi que la politica es estricta.
    $csp = "default-src 'none'; "
         . "script-src 'self'; "
         . "style-src 'self'" . ($allowInlineStyle ? " 'unsafe-inline'" : '') . '; '
         . "img-src 'self' data:; "
         . "connect-src 'self'; "
         . "font-src 'self'; "
         . "form-action 'self'; "
         . "frame-ancestors 'none'; "
         . "base-uri 'none'";
    header('Content-Security-Policy: ' . $csp);
    // Nada de cache en el navegador: se prefiere el coste de trafico a mostrar
    // datos viejos. El panel refleja el estado del servidor y una version
    // guardada puede enganar sobre incidencias ya resueltas o ya presentes.
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), interest-cohort=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header_remove('X-Powered-By');
    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if (trusted_proxy_request() && strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
        return true;
    }
    return (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
}

// ------------------------------------------------------------ IP de origen --

/** ¿La conexion viene de un proxy en el que confiamos? */
function trusted_proxy_request(): bool
{
    global $CFG;
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    foreach ($CFG['trusted_proxies'] ?? [] as $cidr) {
        if (ip_in_cidr($remote, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * IP real del cliente. Solo se hace caso de las cabeceras de reenvio cuando
 * la conexion procede de un proxy declarado como de confianza; de lo contrario
 * cualquiera podria falsear su origen enviando X-Forwarded-For.
 */
function client_ip(): string
{
    $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    if (!trusted_proxy_request()) {
        return $remote;
    }
    // Cloudflare
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])
        && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = array_map('trim', explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']));
        foreach (array_reverse($parts) as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return $remote;
}

/** Comprueba pertenencia a un CIDR (IPv4 e IPv6). */
function ip_in_cidr(string $ip, string $cidr): bool
{
    if ($ip === '' || $cidr === '') {
        return false;
    }
    if (!str_contains($cidr, '/')) {
        return $ip === $cidr;
    }
    [$net, $bits] = explode('/', $cidr, 2);
    $bits = (int) $bits;

    $ipBin  = @inet_pton($ip);
    $netBin = @inet_pton($net);
    if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin)) {
        return false;
    }

    $bytes = intdiv($bits, 8);
    $rem   = $bits % 8;
    if ($bytes > 0 && strncmp($ipBin, $netBin, $bytes) !== 0) {
        return false;
    }
    if ($rem === 0) {
        return true;
    }
    $mask = ~((1 << (8 - $rem)) - 1) & 0xFF;
    return (ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
}

/** ¿La IP esta permitida por la allowlist? Lista vacia = sin restriccion. */
function ip_allowed(): bool
{
    global $CFG;
    $list = $CFG['ip_allowlist'] ?? [];
    if (!$list) {
        return true;
    }
    $ip = client_ip();
    foreach ($list as $cidr) {
        if (ip_in_cidr($ip, (string) $cidr)) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------- estado ---

/** Lee el JSON que dejo el colector. */
function read_state(): ?array
{
    global $CFG;
    $f = rtrim($CFG['state_dir'], '/') . '/state.json';
    if (!is_readable($f)) {
        return null;
    }
    $d = json_decode((string) file_get_contents($f), true);
    return is_array($d) ? $d : null;
}

/**
 * Ruta dentro de la cola de peticiones al colector.
 *
 * Es el unico sitio del directorio de estado donde la web escribe para pedir
 * trabajo privilegiado. El instalador lo crea con el grupo del panel y el bit
 * setgid; si no existe, devolvemos cadena vacia y quien llama avisa.
 */
function queue_path(string $name): string
{
    global $CFG;
    $dir = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/queue';
    if (!is_dir($dir) || !is_writable($dir)) {
        return '';
    }
    return $dir . '/' . basename($name);
}

/**
 * Ruta de una peticion de accion (bloquear o desbloquear una IP).
 *
 * Van en su propio directorio porque systemd lo vigila con DirectoryNotEmpty:
 * en cuanto aparece un fichero, arranca el ejecutor privilegiado.
 */
function action_queue_path(string $id): string
{
    global $CFG;
    $dir = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/queue/actions';
    if (!is_dir($dir) || !is_writable($dir) || !preg_match('/^[a-f0-9]{8,32}$/', $id)) {
        return '';
    }
    return $dir . '/' . $id . '.json';
}

/** Resultados de las ultimas acciones, tal como los dejo el ejecutor. */
function read_actions(): array
{
    global $CFG;
    $f = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/actions.json';
    if (!is_readable($f)) {
        return [];
    }
    $d = json_decode((string) file_get_contents($f), true);
    return is_array($d) ? $d : [];
}

/**
 * Progreso de una correccion larga.
 *
 * El fichero lo escribe el trabajo mientras corre; aqui solo se lee. Como
 * cualquier otra cosa del directorio de estado, si no se puede leer se
 * devuelve null y quien llama decide que contar.
 */
function read_job(string $id): ?array
{
    global $CFG;
    if (!preg_match('/^[a-f0-9]{8,32}$/', $id)) {
        return null;
    }
    $f = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/jobs/' . $id . '.json';
    if (!is_readable($f)) {
        return null;
    }
    $d = json_decode((string) file_get_contents($f), true);
    return is_array($d) ? $d : null;
}

/** Edad del estado en segundos, o null si no hay estado. */
function state_age(?array $st): ?int
{
    return isset($st['generated_at']) ? max(0, time() - (int) $st['generated_at']) : null;
}

/** Respuesta JSON y fin. */
function json_out($data, int $code = 200): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * URL de un recurso estatico con marca de version.
 *
 * Sin esto el navegador conserva el CSS anterior de su cache en memoria y los
 * cambios de estilo no se ven hasta un recargado forzado.
 */
function asset(string $path): string
{
    // Marca unica por peticion en lugar de por fecha del fichero: con
    // filemtime el navegador conserva su copia entre despliegues, y aqui se
    // quiere siempre la version vigente. Cuesta una descarga por visita.
    static $nonce = null;
    if ($nonce === null) {
        $nonce = bin2hex(random_bytes(4));
    }
    $abs = __DIR__ . '/../' . ltrim($path, '/');
    $v   = @filemtime($abs);
    return h($path) . '?v=' . ($v ?: 0) . '.' . $nonce;
}

/** Escapa para HTML. */
function h($s): string
{
    if (is_array($s) || is_object($s)) {
        $s = '';
    }
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
