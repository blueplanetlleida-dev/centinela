<?php
/**
 * Centinela - configuracion.
 *
 * El instalador genera este fichero en /etc/centinela/config.php con
 * permisos 0640. Contiene el hash de la contrasena y el secreto TOTP:
 * no debe quedar accesible desde la web ni entrar en control de versiones.
 */

return [
    'timezone' => 'Europe/Madrid',

    // Plataforma: 'plesk', 'hestia' o 'generic' (Linux sin panel). Vacio = detectar.
    'platform' => '',

    'auth' => [
        'user'          => 'admin',
        // Generar con: centinela-admin passwd
        'hash'          => '',
        // Secreto TOTP en base32; se muestra como QR al instalar
        'totp_secret'   => '',
        'totp_required' => true,
        'session_ttl'   => 7200,
    ],

    // Vacia = sin filtro por IP en la aplicacion.
    // Ejemplo: ['203.0.113.0/24', '198.51.100.7']
    'ip_allowlist' => [],

    // Si hay un proxy delante (Cloudflare, balanceador), sus rangos van aqui
    // para que la IP real del visitante se lea de las cabeceras.
    'trusted_proxies' => [],

    // Bloqueos desde el panel y la geo-valla.
    'actions' => [
        // Jail de fail2ban. Vacio = el de la plataforma: plesk-permanent-ban
        // en Plesk, «centinela» (lo crea el instalador) en el resto.
        'jail'      => '',
        'never_ban' => [],
    ],

    // Sin panel: patrones (glob) de los logs web y de los certificados, si no
    // estan en /var/log/nginx, /var/log/apache2 o /etc/letsencrypt/live.
    'web'   => ['logs'  => []],
    'certs' => ['paths' => []],

    'mail' => [
        'enabled'        => true,
        // OBLIGATORIO: administrador que recibe alertas e informe semanal.
        'to'             => ['admin@ejemplo.com'],
        'from'           => '',
        'weekly'         => true,
        'weekly_day'     => 1,   // 1 lunes ... 7 domingo
        'weekly_hour'    => 8,
        'alerts'         => true,
        'alert_min_sev'  => 'warn',
        'alert_throttle' => 86400,
    ],

    'lg' => [
        'enabled'    => true,
        'public'     => true,
        'per_minute' => 10,
        'per_hour'   => 60,
    ],
];
