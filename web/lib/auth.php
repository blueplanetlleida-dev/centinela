<?php
/**
 * Centinela - autenticacion del panel privado.
 *
 * Contrasena con bcrypt, segundo factor TOTP y bloqueo por intentos.
 * Todos los intentos, correctos o no, quedan registrados.
 */

declare(strict_types=1);

const CENT_SESSION_NAME = 'centinela_sid';

/** Arranca la sesion con parametros endurecidos. */
function session_start_secure(): void
{
    global $CFG;
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $dir = rtrim($CFG['state_dir'], '/') . '/sessions';
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }
    if (is_writable($dir)) {
        session_save_path($dir);
    }

    session_name(CENT_SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_maxlifetime', (string) (int) ($CFG['auth']['session_ttl'] ?? 7200));
    session_start();
}

/** Registro de accesos, para auditoria. */
function auth_log(string $event, string $user = '', string $detail = ''): void
{
    global $CFG;

    // Un evento por linea y campos separados por tabulador: hay que neutralizar
    // ambos separadores en todo lo que venga de fuera. Sin esto, un salto de
    // linea en el nombre de usuario permite inventarse registros completos
    // (por ejemplo un login_ok desde otra IP) que el panel pinta como buenos.
    $clean = static fn(string $s, int $max): string =>
        substr(str_replace(["\t", "\n", "\r", "\v", "\f", "\0"], ' ', $s), 0, $max);

    $line = sprintf(
        "%s\t%s\t%s\t%s\t%s\t%s\n",
        date('c'),
        $clean($event, 32),
        $clean(client_ip(), 45),
        $clean($user, 64),
        $clean((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 120),
        $clean($detail, 200)
    );
    $f = rtrim($CFG['state_dir'], '/') . '/access.log';
    @file_put_contents($f, $line, FILE_APPEND | LOCK_EX);
    @chmod($f, 0640);
}

/** ¿Hay una sesion valida? */
function is_authenticated(): bool
{
    global $CFG;
    session_start_secure();

    if (empty($_SESSION['auth']) || empty($_SESSION['uid'])) {
        return false;
    }
    $ttl = (int) ($CFG['auth']['session_ttl'] ?? 7200);
    if (time() - (int) ($_SESSION['login_at'] ?? 0) > $ttl) {
        auth_logout();
        return false;
    }
    // Atamos la sesion al agente para dificultar el robo de cookie
    if (($_SESSION['ua'] ?? '') !== substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 120)) {
        auth_logout();
        return false;
    }
    $_SESSION['last_seen'] = time();
    return true;
}

/** Exige sesion; si no la hay redirige al login. */
function require_auth(): void
{
    if (!ip_allowed()) {
        http_response_code(403);
        auth_log('denied_ip');
        exit('Acceso no permitido desde esta direccion.');
    }
    if (!is_authenticated()) {
        header('Location: login.php');
        exit;
    }
}

/** Clave de bloqueo por IP. */
function lockout_key(): string
{
    return 'login:' . client_ip();
}

/** ¿Esta bloqueado el origen por exceso de intentos? */
function is_locked_out(): bool
{
    global $CFG;
    $max = (int) ($CFG['auth']['max_attempts'] ?? 5);
    $win = (int) ($CFG['auth']['lockout'] ?? 900);
    return rl_remaining(lockout_key(), $max, $win) <= 0;
}

/**
 * Intenta autenticar. Devuelve ['ok'=>bool, 'error'=>string].
 * Consume una unidad del contador de intentos en cada fallo.
 */
function auth_attempt(string $user, string $pass, string $code): array
{
    global $CFG;

    if (is_locked_out()) {
        auth_log('lockout', $user);
        return ['ok' => false, 'error' => 'Demasiados intentos. Prueba de nuevo mas tarde.'];
    }

    /*
     * Cuentas admitidas: la historica de auth.user/hash mas las del mapa
     * auth.users, cada una con su contrasena y su secreto TOTP propios.
     */
    $accounts = [];
    $legacyUser = (string) ($CFG['auth']['user'] ?? '');
    if ($legacyUser !== '' && (string) ($CFG['auth']['hash'] ?? '') !== '') {
        $accounts[$legacyUser] = [
            'hash'          => (string) $CFG['auth']['hash'],
            'totp_secret'   => (string) ($CFG['auth']['totp_secret'] ?? ''),
            'totp_required' => (bool) ($CFG['auth']['totp_required'] ?? true),
        ];
    }
    foreach ((array) ($CFG['auth']['users'] ?? []) as $u => $a) {
        if (is_string($u) && $u !== '' && is_array($a) && !empty($a['hash'])) {
            $accounts[$u] = [
                'hash'          => (string) $a['hash'],
                'totp_secret'   => (string) ($a['totp_secret'] ?? ''),
                'totp_required' => (bool) ($a['totp_required'] ?? true),
            ];
        }
    }

    if (!$accounts) {
        return ['ok' => false, 'error' => 'Centinela no tiene contrasena configurada. Ejecuta: centinela-admin passwd'];
    }

    // Se compara siempre todo, exista o no la cuenta, para que el tiempo de
    // respuesta no delate que nombres de usuario son reales.
    $acc    = $accounts[$user] ?? null;
    $userOk = $acc !== null;
    // Hash de una contrasena aleatoria ya descartada: solo da trabajo a bcrypt.
    $passOk = password_verify($pass, $acc['hash']
        ?? '$2y$12$CDBIs.ac5CE2RVc7ifezheupgnEUpxY91DnNYz1ShJQ9RLv5lXtL6') && $userOk;

    $totpReq = $acc['totp_required'] ?? true;
    $secret  = (string) ($acc['totp_secret'] ?? '');
    $totpOk  = !$totpReq || ($secret !== '' && totp_verify($secret, $code));

    if ($userOk && $totpReq && $secret === '') {
        return ['ok' => false, 'error' => 'El segundo factor es obligatorio pero no hay secreto configurado. Ejecuta: centinela-admin totp'];
    }

    if (!$userOk || !$passOk || !$totpOk) {
        $max = (int) ($CFG['auth']['max_attempts'] ?? 5);
        $win = (int) ($CFG['auth']['lockout'] ?? 900);
        rl_hit(lockout_key(), $max, $win);

        $reason = !$userOk || !$passOk ? 'credenciales' : 'codigo TOTP';
        auth_log('login_fail', $user, $reason);
        // El mensaje al usuario no distingue el motivo
        return ['ok' => false, 'error' => 'Credenciales o codigo incorrectos.'];
    }

    session_start_secure();
    session_regenerate_id(true);
    $_SESSION['auth']     = true;
    $_SESSION['uid']      = $user;
    $_SESSION['login_at'] = time();
    $_SESSION['ua']       = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 120);
    $_SESSION['csrf']     = bin2hex(random_bytes(32));

    auth_log('login_ok', $user);
    return ['ok' => true, 'error' => ''];
}

function auth_logout(): void
{
    session_start_secure();
    $user = $_SESSION['uid'] ?? '';
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    if ($user !== '') {
        auth_log('logout', (string) $user);
    }
}

/** Token CSRF de la sesion actual. */
function csrf_token(): string
{
    session_start_secure();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_check(?string $token): bool
{
    session_start_secure();
    return is_string($token) && !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

/** Ultimas lineas del registro de accesos. */
function recent_access_log(int $limit = 30): array
{
    global $CFG;
    $f = rtrim($CFG['state_dir'], '/') . '/access.log';
    if (!is_readable($f)) {
        return [];
    }
    $lines = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $out = [];
    foreach (array_slice($lines, -$limit) as $l) {
        $p = explode("\t", $l);
        if (count($p) >= 4) {
            $out[] = ['time' => $p[0], 'event' => $p[1], 'ip' => $p[2], 'user' => $p[3], 'detail' => $p[5] ?? ''];
        }
    }
    return array_reverse($out);
}
