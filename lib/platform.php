<?php
/**
 * Centinela - capa de plataforma.
 *
 * Todo lo que depende del panel de hosting (o de su ausencia) pasa por aqui:
 * que panel hay, donde estan los logs web, que dominios se alojan, que jail
 * de fail2ban recibe los bloqueos manuales. Los modulos del colector hacen
 * las preguntas y esta capa responde segun la plataforma; asi el resto del
 * codigo no sabe si corre en Plesk, en HestiaCP o en un Ubuntu con los
 * servicios instalados a mano.
 *
 * La plataforma la fija el instalador en config.php ('platform'); si falta,
 * se detecta. La variable de entorno CENTINELA_PLATFORM la fuerza (pruebas).
 */

declare(strict_types=1);

const CENT_PLATFORMS = [
    'plesk'   => 'Plesk',
    'hestia'  => 'HestiaCP',
    'generic' => 'Linux sin panel',
];

/** Ruta del binario plesk, o null si no esta instalado. */
function plesk_bin(): ?string
{
    foreach (['/usr/sbin/plesk', '/usr/local/psa/bin/plesk', '/opt/psa/bin/plesk'] as $p) {
        if (is_executable($p)) {
            return $p;
        }
    }
    return null;
}

/** Ruta de una utilidad de HestiaCP (v-list-users, ...), o null. */
function hestia_bin(string $cmd): ?string
{
    $p = '/usr/local/hestia/bin/' . basename($cmd);
    return is_executable($p) ? $p : null;
}

/** Detecta la plataforma mirando el sistema, sin consultar la configuracion. */
function platform_detect(): string
{
    if (plesk_bin() !== null) {
        return 'plesk';
    }
    if (hestia_bin('v-list-users') !== null) {
        return 'hestia';
    }
    return 'generic';
}

/** Plataforma vigente: entorno > configuracion > deteccion. */
function platform(): string
{
    static $p = null;
    if ($p !== null) {
        return $p;
    }
    $env = (string) getenv('CENTINELA_PLATFORM');
    if (isset(CENT_PLATFORMS[$env])) {
        return $p = $env;
    }
    $cfg = function_exists('load_config') ? load_config() : [];
    $c   = (string) ($cfg['platform'] ?? '');
    if (isset(CENT_PLATFORMS[$c])) {
        return $p = $c;
    }
    return $p = platform_detect();
}

function platform_is(string $key): bool
{
    return platform() === $key;
}

function platform_label(?string $key = null): string
{
    return CENT_PLATFORMS[$key ?? platform()] ?? 'desconocida';
}

/**
 * Elige un texto segun la plataforma. Las claves son 'plesk', 'hestia',
 * 'generic'; si falta la de la plataforma actual se usa 'generic'.
 * Sirve para que las guias de solucion den el comando de cada panel.
 */
function platform_text(array $byPlatform): string
{
    return (string) ($byPlatform[platform()] ?? $byPlatform['generic'] ?? reset($byPlatform) ?: '');
}

// ------------------------------------------------------------------ Hestia --

/** Usuarios de HestiaCP. */
function hestia_users(): array
{
    static $users = null;
    if ($users !== null) {
        return $users;
    }
    $users = [];
    $bin = hestia_bin('v-list-users');
    if ($bin === null) {
        return $users;
    }
    $d = json_decode(run([$bin, 'json'], 20)['out'], true);
    if (is_array($d)) {
        $users = array_values(array_filter(array_keys($d), fn($u) => preg_match('/^[a-zA-Z0-9_.-]+$/', (string) $u)));
    }
    return $users;
}

/** Version instalada de HestiaCP, leida de su fichero de configuracion. */
function hestia_version(): ?string
{
    $raw = slurp('/usr/local/hestia/conf/hestia.conf', 65536);
    if ($raw === null) {
        return null;
    }
    return match1("/^VERSION='?([0-9][0-9.]*)'?/m", $raw);
}

// ------------------------------------------------------------- logs web ----

/**
 * Ficheros de log web a leer, por dominio:
 *   [ ['domain' => nombre, 'file' => ruta, 'kind' => 'access'|'error'], ... ]
 *
 * Plesk: nginx delante y Apache detras; se leen los de Apache porque ven las
 * peticiones dinamicas, y los .processed son la parte del dia ya rotada.
 * Hestia: /var/log/{apache2,nginx}/domains/DOMINIO.log y DOMINIO.error.log;
 * se prefiere Apache si existe (es el backend), si no nginx.
 * Sin panel: los access/error de nginx y Apache, mas los patrones que el
 * administrador anada en config.php ('web' => ['logs' => [...]]).
 */
function platform_web_logs(): array
{
    $out = [];
    switch (platform()) {
        case 'plesk':
            foreach (glob('/var/www/vhosts/*/logs/*', GLOB_ONLYDIR) ?: [] as $dir) {
                $dominio = basename($dir);
                foreach (['access_ssl_log', 'access_ssl_log.processed', 'access_log', 'access_log.processed'] as $n) {
                    if (is_readable($dir . '/' . $n)) {
                        $out[] = ['domain' => $dominio, 'file' => $dir . '/' . $n, 'kind' => 'access'];
                    }
                }
                foreach (['error_log', 'error_log.processed'] as $n) {
                    if (is_readable($dir . '/' . $n)) {
                        $out[] = ['domain' => $dominio, 'file' => $dir . '/' . $n, 'kind' => 'error'];
                    }
                }
            }
            break;

        case 'hestia':
            $dirs = array_filter(['/var/log/apache2/domains', '/var/log/httpd/domains', '/var/log/nginx/domains'], 'is_dir');
            // Solo el backend: si Apache existe, nginx solo hace de proxy y
            // repetiria cada peticion.
            $dir = reset($dirs);
            foreach ($dir ? (glob($dir . '/*.log') ?: []) : [] as $f) {
                if (!is_readable($f)) {
                    continue;
                }
                $b = basename($f, '.log');
                $kind = 'access';
                if (str_ends_with($b, '.error')) {
                    $kind = 'error';
                    $b = substr($b, 0, -6);
                }
                if (str_ends_with($b, '.ssl')) {
                    $b = substr($b, 0, -4);
                }
                if ($b === '' || $b[0] === '.') {
                    continue;
                }
                $out[] = ['domain' => $b, 'file' => $f, 'kind' => $kind];
            }
            break;

        default:
            $cfg = load_config();
            $globs = (array) ($cfg['web']['logs'] ?? []);
            if (!$globs) {
                $globs = [
                    '/var/log/nginx/*access*.log', '/var/log/nginx/*error*.log',
                    '/var/log/apache2/*access*.log', '/var/log/apache2/*error*.log',
                    '/var/log/httpd/*access*log', '/var/log/httpd/*error*log',
                ];
            }
            $host = php_uname('n');
            foreach ($globs as $g) {
                foreach (glob((string) $g) ?: [] as $f) {
                    if (!is_file($f) || !is_readable($f) || preg_match('/\.(gz|\d+|bz2|xz)$/', $f)) {
                        continue;
                    }
                    $b = basename($f);
                    $kind = str_contains($b, 'error') ? 'error' : 'access';
                    // «midominio.com-access.log» -> «midominio.com»; «access.log» -> hostname
                    $dom = preg_replace('/[-_.]?(access|error)[-_.]?(ssl)?[-_.]?(log)?(\.log)?$/i', '', $b);
                    $dom = preg_replace('/^(ssl[-_.]?|other_vhosts[-_.]?)/i', '', (string) $dom);
                    $dom = trim((string) $dom, '-_.');
                    $out[] = ['domain' => $dom !== '' && $dom !== 'log' ? $dom : $host, 'file' => $f, 'kind' => $kind];
                }
            }
    }
    return $out;
}

/** Patron de los logs de acceso, para los comandos de las guias. */
function platform_weblog_glob(): string
{
    return platform_text([
        'plesk'   => '/var/www/vhosts/*/logs/*/access_ssl_log*',
        'hestia'  => '/var/log/apache2/domains/*.log',
        'generic' => '/var/log/nginx/*access*.log /var/log/apache2/*access*.log',
    ]);
}

/** Como recargar el servidor web tras tocar la configuracion de un dominio. */
function platform_web_reload_cmd(): string
{
    return platform_text([
        'plesk'   => 'plesk sbin httpdmng --reconfigure-domain DOMINIO',
        'hestia'  => 'v-rebuild-web-domains USUARIO',
        'generic' => 'nginx -t && systemctl reload nginx; apache2ctl -t && systemctl reload apache2',
    ]);
}

// ------------------------------------------------------ dominios alojados --

/**
 * Dominios web alojados en plataformas distintas de Plesk (Plesk consulta su
 * propia base de datos en collect_domains). Cada entrada:
 *   ['name' => , 'status' => 'activo'|'suspendido', 'ssl' => bool, 'user' => ]
 */
function platform_web_domains(): array
{
    $out = [];
    if (platform_is('hestia')) {
        $bin = hestia_bin('v-list-web-domains');
        foreach ($bin ? hestia_users() : [] as $u) {
            $d = json_decode(run([$bin, $u, 'json'], 20)['out'], true);
            foreach (is_array($d) ? $d : [] as $name => $info) {
                if (!is_array($info)) {
                    continue;
                }
                $out[] = [
                    'name'   => (string) $name,
                    'status' => (($info['SUSPENDED'] ?? 'no') === 'yes') ? 'suspendido' : 'activo',
                    'ssl'    => (($info['SSL'] ?? 'no') === 'yes'),
                    'user'   => $u,
                ];
            }
        }
        return $out;
    }
    if (!platform_is('generic')) {
        return $out;
    }

    // Apache: «port 443 namevhost midominio.com (/etc/apache2/sites-enabled/...)»
    $names = [];
    $apache = sh('apache2ctl -S 2>/dev/null || httpd -S 2>/dev/null', 15);
    if (preg_match_all('/port\s+(\d+)\s+namevhost\s+(\S+)/', $apache, $mm, PREG_SET_ORDER)) {
        foreach ($mm as $m) {
            $n = strtolower($m[2]);
            $names[$n] = ($names[$n] ?? false) || $m[1] === '443';
        }
    }
    // nginx: bloques server { server_name ...; listen ... ssl; }
    $ngx = sh('nginx -T 2>/dev/null', 20);
    if ($ngx !== '') {
        foreach (array_slice(preg_split('/\bserver\s*\{/', $ngx) ?: [], 1) as $blk) {
            $blk = substr($blk, 0, 6000);
            $ssl = (bool) preg_match('/\blisten\s+[^;]*\bssl\b|\bssl_certificate\s/', $blk);
            if (!preg_match_all('/\bserver_name\s+([^;]+);/', $blk, $sm)) {
                continue;
            }
            foreach ($sm[1] as $lista) {
                foreach (preg_split('/\s+/', trim($lista)) ?: [] as $n) {
                    $n = strtolower($n);
                    if ($n === '' || $n === '_' || $n === 'localhost' || $n[0] === '~' || !str_contains($n, '.')) {
                        continue;
                    }
                    $names[$n] = ($names[$n] ?? false) || $ssl;
                }
            }
        }
    }
    ksort($names);
    foreach ($names as $n => $ssl) {
        if (preg_match('/^[a-z0-9*][a-z0-9.*-]*$/', $n)) {
            $out[] = ['name' => $n, 'status' => 'activo', 'ssl' => $ssl, 'user' => ''];
        }
    }
    return $out;
}

/** Dominios de correo alojados, para revisar SPF, DKIM y DMARC. */
function platform_mail_domains(int $limit = 10): array
{
    $doms = [];
    switch (platform()) {
        case 'plesk':
            $bin = plesk_bin();
            if ($bin !== null) {
                $out = run([$bin, 'db', '-Ne',
                    "SELECT d.name FROM domains d JOIN mail m ON m.dom_id = d.id
                     WHERE d.parentDomainId = 0 GROUP BY d.name LIMIT {$limit}"], 20)['out'];
                $doms = array_map('trim', explode("\n", $out));
            }
            break;

        case 'hestia':
            $bin = hestia_bin('v-list-mail-domains');
            foreach ($bin ? hestia_users() : [] as $u) {
                $d = json_decode(run([$bin, $u, 'json'], 20)['out'], true);
                foreach (is_array($d) ? array_keys($d) : [] as $name) {
                    if ((($d[$name]['SUSPENDED'] ?? 'no') !== 'yes')) {
                        $doms[] = (string) $name;
                    }
                }
            }
            break;

        default:
            if (have('postconf')) {
                $raw = sh('postconf -xh mydomain virtual_mailbox_domains virtual_alias_domains relay_domains 2>/dev/null', 10);
                foreach (preg_split('/[\s,]+/', $raw) ?: [] as $tok) {
                    // Se saltan las referencias a mapas (hash:/etc/..., mysql:...) y variables
                    if ($tok === '' || str_contains($tok, ':') || str_contains($tok, '$')) {
                        continue;
                    }
                    $doms[] = strtolower($tok);
                }
            }
            if (!$doms) {
                $h = php_uname('n');
                if (substr_count($h, '.') >= 1) {
                    $doms[] = strtolower(substr_count($h, '.') >= 2 ? substr($h, strpos($h, '.') + 1) : $h);
                }
            }
    }
    $doms = array_values(array_unique(array_filter($doms, fn($d) => preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $d))));
    return array_slice($doms, 0, $limit);
}

/** Selectores DKIM que usa cada plataforma por defecto, en orden de prueba. */
function platform_dkim_selectors(): array
{
    return match (platform()) {
        'plesk'  => ['default'],
        'hestia' => ['mail'],
        default  => ['default', 'mail', 'dkim', 'selector1', 's1'],
    };
}

// ------------------------------------------------------------ certificados --

/** Ficheros PEM cuyos certificados hay que vigilar. */
function platform_cert_files(): array
{
    $files = [];
    switch (platform()) {
        case 'plesk':
            foreach (['/usr/local/psa', '/opt/psa'] as $root) {
                if (is_dir($root)) {
                    $files = glob($root . '/var/certificates/*') ?: [];
                    break;
                }
            }
            break;
        case 'hestia':
            $files = array_merge(
                glob('/home/*/conf/web/*/ssl/*.crt') ?: [],
                glob('/usr/local/hestia/ssl/certificate.crt') ?: []
            );
            break;
        default:
            $cfg   = load_config();
            $globs = (array) ($cfg['certs']['paths'] ?? []);
            if (!$globs) {
                $globs = [
                    '/etc/letsencrypt/live/*/cert.pem',
                    '/etc/nginx/ssl/*.crt', '/etc/nginx/ssl/*.pem',
                    '/etc/apache2/ssl/*.crt', '/etc/apache2/ssl/*.pem',
                    '/etc/ssl/certs/*.crt',
                ];
            }
            foreach ($globs as $g) {
                $files = array_merge($files, glob((string) $g) ?: []);
            }
            // El almacen de CAs del sistema no es nuestro
            $files = array_filter($files, fn($f) => !str_starts_with((string) realpath($f), '/usr/share/ca-certificates'));
    }
    return array_values(array_unique(array_filter($files, 'is_file')));
}

// ------------------------------------------------------------------- PHP ----

/**
 * Versiones de PHP instaladas: [ '8.3' => ['version'=>'8.3', 'full'=>'8.3.12', 'status'=>...] ].
 * En Plesk las lista su gestor de handlers; en el resto se buscan los
 * interpretes instalados (Debian/Ubuntu en /usr/bin/phpX.Y, Remi en /opt/remi).
 */
function platform_php_versions(): array
{
    $versions = [];
    if (platform_is('plesk')) {
        $bin = plesk_bin();
        $out = $bin ? run([$bin, 'bin', 'php_handler', '--list'], 25)['out'] : '';
        foreach (explode("\n", $out) as $line) {
            $f = preg_split('/\s{2,}/', trim($line));
            if (count($f) < 5 || !preg_match('/^\d+\.\d+/', $f[2] ?? '')) {
                continue;
            }
            $v = $f[3] ?? '';
            if ($v !== '' && !isset($versions[$v])) {
                $versions[$v] = ['version' => $v, 'full' => $f[2], 'status' => trim((string) end($f))];
            }
        }
        return $versions;
    }

    $bins = array_merge(
        glob('/usr/bin/php[0-9].[0-9]') ?: [],
        glob('/usr/bin/php[0-9].[0-9][0-9]') ?: [],
        glob('/opt/remi/php[0-9][0-9]/root/usr/bin/php') ?: [],
        glob('/opt/plesk/php/*/bin/php') ?: [],
        is_executable('/usr/bin/php') ? ['/usr/bin/php'] : []
    );
    foreach ($bins as $b) {
        $full = trim(run([$b, '-n', '-r', 'echo PHP_VERSION;'], 10)['out']);
        if (!preg_match('/^(\d+\.\d+)\.\d+/', $full, $m)) {
            continue;
        }
        $v = $m[1];
        if (isset($versions[$v])) {
            continue;
        }
        // ¿Hay un pool FPM corriendo con esa version?
        $fpm = trim(run(['/usr/bin/systemctl', 'is-active', "php{$v}-fpm"], 5)['out']);
        $versions[$v] = [
            'version' => $v,
            'full'    => $full,
            'status'  => $fpm === 'active' ? 'fpm activo' : 'instalado',
            'bin'     => $b,
        ];
    }
    return $versions;
}

// ------------------------------------------------------------- fail2ban ----

/** Jail donde caen los bloqueos manuales si la configuracion no dice otro. */
function platform_default_jail(): string
{
    return platform_is('plesk') ? 'plesk-permanent-ban' : 'centinela';
}

/** Jail configurado para los bloqueos del panel y de la geo-valla. */
function ban_jail(): string
{
    $cfg = function_exists('load_config') ? load_config() : [];
    $j = trim((string) ($cfg['actions']['jail'] ?? ''));
    return $j !== '' ? $j : platform_default_jail();
}

// ----------------------------------------------------------------- PHP-FPM --

/** Unidades PHP-FPM en marcha, para recargarlas tras cambiar el codigo web. */
function platform_fpm_units(): array
{
    $out = run(['/usr/bin/systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain'], 10)['out'];
    $units = [];
    foreach (explode("\n", $out) as $l) {
        $u = strtok(trim($l), ' ');
        if ($u && preg_match('/^(plesk-php\d+-fpm|php[\d.]*-fpm)\.service$/', $u)) {
            $units[] = $u;
        }
    }
    return $units;
}

// ------------------------------------------------------------- modulo panel --

/**
 * Modulo del colector: que panel hay y si esta al dia. Plesk tiene su propio
 * modulo (collect_plesk) con mas detalle; aqui se cubre Hestia y se deja
 * constancia de la plataforma para el panel y el informe.
 */
function collect_panel(): array
{
    $res = [
        'platform' => platform(),
        'label'    => platform_label(),
        'version'  => null,
        'updates'  => [],
        'findings' => [],
    ];
    if (!platform_is('hestia')) {
        return $res;
    }
    $res['version'] = hestia_version();

    $bin = hestia_bin('v-list-sys-hestia-updates');
    if ($bin !== null) {
        $d = cached('hestia_updates', 21600, function () use ($bin) {
            $j = json_decode(run([$bin, 'json'], 60)['out'], true);
            return is_array($j) ? $j : [];
        }, true) ?: [];
        $pend = [];
        foreach ($d as $pkg => $info) {
            if (is_array($info) && (($info['UPDATED'] ?? 'yes') === 'no')) {
                $pend[] = (string) $pkg . (isset($info['VERSION']) ? ' ' . $info['VERSION'] : '');
            }
        }
        $res['updates'] = $pend;
        if ($pend) {
            $res['findings'][] = finding('panel.update', SEV_WARN,
                'Actualizacion de HestiaCP disponible',
                'Paquetes pendientes: ' . implode(', ', array_slice($pend, 0, 5)),
                'v-update-sys-hestia-all',
                guide(
                    'El panel es la pieza con mas superficie expuesta del servidor y la que gestiona todas las '
                    . 'contrasenas: sus actualizaciones traen las correcciones de seguridad que mas importan.',
                    [
                        ['do' => 'Mira que hay pendiente', 'cmd' => 'v-list-sys-hestia-updates'],
                        ['do' => 'Aplica la actualizacion', 'cmd' => 'v-update-sys-hestia-all'],
                        ['do' => 'Comprueba que el panel responde', 'cmd' => 'systemctl status hestia --no-pager | head -5'],
                    ],
                    'v-list-sys-hestia-updates | grep -c " no "',
                    'La actualizacion reinicia el servicio del panel; hazla fuera de horas de trabajo de tus usuarios.',
                    'https://hestiacp.com/docs/'
                ));
        }
    }
    return $res;
}
