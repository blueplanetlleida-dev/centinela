<?php
/**
 * Centinela - carga de configuracion.
 * Compartido por el colector (root) y la capa web (usuario del dominio).
 */

declare(strict_types=1);

function config_paths(): array
{
    return [
        getenv('CENTINELA_CONFIG') ?: '',
        '/etc/centinela/config.php',
        dirname(__DIR__) . '/config/config.php',
    ];
}

/** Carga la configuracion aplicando los valores por defecto. */
function load_config(): array
{
    static $cfg = null;
    if ($cfg !== null) {
        return $cfg;
    }

    $user = [];
    foreach (config_paths() as $p) {
        if ($p !== '' && is_readable($p)) {
            $c = require $p;
            if (is_array($c)) {
                $user = $c;
                $user['_file'] = $p;
                break;
            }
        }
    }

    $defaults = [
        'app_name'   => 'Centinela',
        'state_dir'  => '/var/lib/centinela',
        'timezone'   => 'Europe/Madrid',
        'locale'     => 'es',
        // 'plesk' | 'hestia' | 'generic'. Vacio = detectar.
        'platform'   => '',

        // Acciones sobre IPs desde el panel y la geo-valla.
        'actions' => [
            'jail'      => '',   // vacio = el de la plataforma (plesk-permanent-ban o centinela)
            'never_ban' => [],
        ],

        // Sin panel: patrones de los logs web si no estan en los sitios habituales.
        'web'   => ['logs'  => []],
        // Sin panel: rutas de certificados a vigilar si no estan en los sitios habituales.
        'certs' => ['paths' => []],

        'auth' => [
            'user'          => 'admin',
            'hash'          => '',      // password_hash(..., PASSWORD_BCRYPT, ['cost'=>12])
            'totp_secret'   => '',      // base32
            'totp_required' => true,
            'session_ttl'   => 7200,
            'max_attempts'  => 5,
            'lockout'       => 900,
        ],

        // Vacia por defecto: el filtrado se hace en el cortafuegos de red.
        'ip_allowlist' => [],

        // Redes cuyo encabezado X-Forwarded-For nos creemos (Cloudflare, proxys).
        'trusted_proxies' => [],

        'mail' => [
            'enabled'        => true,
            'to'             => [],     // OBLIGATORIO: admin del sistema
            'from'           => '',     // por defecto centinela@<hostname>
            'from_name'      => 'Centinela',
            'weekly'         => true,
            'weekly_day'     => 1,      // 1 = lunes
            'weekly_hour'    => 8,
            'alerts'         => true,
            'alert_min_sev'  => 'warn', // warn | crit
            'alert_throttle' => 86400,  // no repetir la misma incidencia antes de 24 h
        ],

        'lg' => [
            'enabled'    => true,
            'public'     => true,
            'per_minute' => 10,
            'per_hour'   => 60,
            'timeout'    => 12,
        ],
    ];

    $cfg = merge_config($defaults, $user);

    if (!empty($cfg['timezone'])) {
        @date_default_timezone_set($cfg['timezone']);
    }
    return $cfg;
}

/** Mezcla recursiva conservando los valores del usuario. */
function merge_config(array $base, array $over): array
{
    foreach ($over as $k => $v) {
        $base[$k] = (is_array($v) && isset($base[$k]) && is_array($base[$k]) && !array_is_list($v))
            ? merge_config($base[$k], $v)
            : $v;
    }
    return $base;
}

/** Destinatarios de correo normalizados. */
function mail_recipients(array $cfg): array
{
    $to = $cfg['mail']['to'] ?? [];
    if (is_string($to)) {
        $to = preg_split('/[,\s;]+/', $to) ?: [];
    }
    return array_values(array_filter(array_map('trim', $to), fn($e) => filter_var($e, FILTER_VALIDATE_EMAIL)));
}
