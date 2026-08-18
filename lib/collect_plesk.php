<?php
/**
 * Centinela - recoleccion especifica de Plesk: version, actualizaciones,
 * dominios, certificados, versiones de PHP y productos de seguridad.
 */

declare(strict_types=1);

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

/** Directorio raiz de Plesk. */
function plesk_root(): ?string
{
    foreach (['/usr/local/psa', '/opt/psa'] as $d) {
        if (is_dir($d)) {
            return $d;
        }
    }
    return null;
}

/** Version instalada y si hay una release mas nueva disponible. */
function collect_plesk(): array
{
    $bin = plesk_bin();
    if ($bin === null) {
        return ['installed' => false, 'findings' => []];
    }

    $verRaw  = run([$bin, 'version'], 20)['out'];
    $version = match1('/Product version:\s+Plesk\s+\S+\s+([0-9.]+)/', $verRaw) ?? '';
    $edition = match1('/Product version:\s+Plesk\s+(\S+)/', $verRaw) ?? '';
    $build   = match1('/Build date:\s+(\S+)/', $verRaw) ?? '';

    // La consulta de releases sale a la red y tarda casi un minuto: la
    // cacheamos 6 horas y la marcamos como externa, para que una
    // recomprobacion a peticion no la vuelva a pedir. Lo que publique Plesk
    // no cambia porque aqui se arregle nada.
    $releases = cached('plesk_releases', 21600, function () use ($bin) {
        $out = run([$bin, 'installer', '--select-product-id', 'plesk', '--show-releases'], 120)['out'];
        $list = [];
        foreach (explode("\n", $out) as $line) {
            if (preg_match('/^plesk\s+(\S+)\s+\((.*?)\)\s+\((.*?)\)/', trim($line), $m)) {
                $list[] = [
                    'id'      => $m[1],
                    'name'    => trim($m[2]),
                    'tier'    => trim($m[3]),
                    'current' => str_contains($m[3], 'currently installed'),
                ];
            }
        }
        return $list;
    }, true) ?: [];

    // La release estable mas alta frente a la instalada
    $latest = null;
    foreach ($releases as $r) {
        if (!str_contains($r['tier'], 'stable')) {
            continue;
        }
        $v = match1('/([0-9]+\.[0-9]+\.[0-9]+)/', $r['name']) ?? match1('/PLESK_([0-9_]+)/', $r['id']);
        $v = $v ? str_replace('_', '.', $v) : null;
        if ($v && ($latest === null || vnum($v) > vnum($latest['version']))) {
            $latest = ['version' => $v, 'name' => $r['name'], 'id' => $r['id']];
        }
    }

    $short   = implode('.', array_slice(explode('.', $version), 0, 3));
    $upgrade = ($latest && vnum($latest['version']) > vnum($short)) ? $latest : null;

    $findings = [];
    if ($upgrade) {
        $findings[] = finding('plesk.update', SEV_WARN,
            "{$upgrade['name']} disponible",
            "Instalado {$version}",
            'plesk installer --select-release-id ' . $upgrade['id'] . ' --install-component base',
            guide(
                'Las versiones nuevas de Plesk traen correcciones de seguridad del propio panel, que es la pieza '
                . 'con mas superficie expuesta del servidor y la que gestiona todas las contrasenas de los clientes.',
                [
                    ['do' => 'Haz copia de la base de datos del panel antes de nada',
                     'cmd' => 'plesk db dump psa | gzip > /root/psa-antes-de-actualizar.sql.gz'],
                    ['do' => 'Comprueba que el servidor cumple los requisitos y que no hay avisos pendientes',
                     'cmd' => 'plesk installer --select-release-current --show-components | head -30'],
                    ['do' => 'Lanza la actualizacion del componente base',
                     'cmd' => 'plesk installer --select-release-id ' . $upgrade['id'] . ' --install-component base'],
                    ['do' => 'Al terminar, revisa que el panel y los servicios web responden',
                     'cmd' => 'plesk version; systemctl status sw-cp-server nginx --no-pager | head -20'],
                ],
                'plesk version | head -2',
                'La actualizacion reinicia el panel y puede reiniciar nginx y PHP-FPM: hazla fuera de horas de '
                . 'trafico y con una copia de seguridad reciente.',
                'https://docs.plesk.com/es-ES/obsidian/administrator-guide/72197/'
            ));
    }

    // Configuracion del actualizador de Plesk
    $misc = plesk_misc(['disable_updater', 'automaticSystemPackageUpdates', 'autoupdater_last_run_date']);
    if (($misc['disable_updater'] ?? '') === 'true') {
        $findings[] = finding('plesk.updater', SEV_WARN, 'Actualizador automatico de Plesk desactivado',
            'Las actualizaciones del panel y sus componentes no se instalan solas',
            'Activar en Herramientas y configuracion > Actualizaciones',
            guide(
                'Con el actualizador apagado, las correcciones del panel se quedan esperando a que alguien entre '
                . 'a aplicarlas a mano. En la practica eso significa meses de retraso.',
                [
                    ['do' => 'Activa las actualizaciones automaticas del panel',
                     'cmd' => 'plesk bin server_pref --update -autoupdates true'],
                    ['do' => 'Elige el nivel en Herramientas y configuracion > Actualizaciones y configuracion de '
                           . 'actualizaciones: lo habitual es instalar solo las de seguridad de forma automatica.'],
                    ['do' => 'Confirma que la marca ha quedado guardada',
                     'cmd' => 'plesk db -Ne "SELECT param, val FROM misc WHERE param IN (\'disable_updater\',\'autoupdater_last_run_date\')"'],
                ],
                'plesk db -Ne "SELECT val FROM misc WHERE param=\'disable_updater\'"'
            ));
    }

    return [
        'installed'    => true,
        'version'      => $version,
        'edition'      => $edition,
        'build_date'   => $build,
        'latest'       => $latest,
        'upgrade'      => $upgrade,
        'updater'      => [
            'disabled'     => ($misc['disable_updater'] ?? 'false') === 'true',
            'auto_syspkg'  => ($misc['automaticSystemPackageUpdates'] ?? '') === 'true',
            'last_run'     => $misc['autoupdater_last_run_date'] ?? null,
        ],
        'findings'     => $findings,
    ];
}

/** Lee claves de la tabla misc de la base de datos de Plesk. */
function plesk_misc(array $keys): array
{
    $bin = plesk_bin();
    if ($bin === null || !$keys) {
        return [];
    }
    $in  = implode(',', array_map(fn($k) => "'" . preg_replace('/[^a-zA-Z0-9_]/', '', $k) . "'", $keys));
    $out = run([$bin, 'db', '-Ne', "SELECT param, val FROM misc WHERE param IN ({$in})"], 20)['out'];
    $res = [];
    foreach (explode("\n", $out) as $line) {
        $f = explode("\t", trim($line));
        if (count($f) >= 2) {
            $res[$f[0]] = $f[1];
        }
    }
    return $res;
}

/** Dominios alojados y su estado. */
function collect_domains(): array
{
    $bin = plesk_bin();
    if ($bin === null) {
        return ['domains' => [], 'findings' => []];
    }

    $out = run([$bin, 'db', '-Ne',
        "SELECT d.name, d.status, d.htype, IFNULL(h.php_handler_id,''), IFNULL(h.ssl,'false')
         FROM domains d LEFT JOIN hosting h ON h.dom_id = d.id ORDER BY d.name"], 25)['out'];

    $domains = [];
    foreach (explode("\n", $out) as $line) {
        $f = explode("\t", trim($line));
        if (count($f) < 2 || $f[0] === '') {
            continue;
        }
        $domains[] = [
            'name'        => $f[0],
            'status'      => (int) $f[1] === 0 ? 'activo' : 'suspendido/desactivado',
            'type'        => $f[2] ?? '',
            'php_handler' => $f[3] ?? '',
            'ssl'         => ($f[4] ?? 'false') === 'true',
        ];
    }

    $noSsl = array_values(array_filter($domains, fn($d) => !$d['ssl'] && $d['status'] === 'activo' && $d['type'] === 'vrt_hst'));
    $findings = [];
    if ($noSsl) {
        $findings[] = finding('dom.nossl', SEV_WARN,
            count($noSsl) . ' dominio(s) sin SSL activo',
            implode(', ', array_slice(array_column($noSsl, 'name'), 0, 8)),
            'Emitir certificado con la extension Let\'s Encrypt',
            guide(
                'Sin certificado, todo lo que se envie a ese dominio viaja en claro, incluidas las contrasenas '
                . 'de sus formularios, y el navegador lo marca como no seguro. Let\'s Encrypt es gratuito y se '
                . 'renueva solo.',
                [
                    ['do' => 'Comprueba antes que cada dominio resuelve a este servidor: sin eso, la emision falla',
                     'cmd' => 'for d in ' . implode(' ', array_map('escapeshellarg', array_slice(array_column($noSsl, 'name'), 0, 8))) . '; do echo -n "$d -> "; dig +short A "$d"; done'],
                    ['do' => 'Emite el certificado de cada uno, con su alias www',
                     'cmd' => 'plesk bin extension --exec letsencrypt cli.php -d DOMINIO -d www.DOMINIO'
                            . ' -m admin@' . implode('.', array_slice(explode('.', php_uname('n')), 1)) . ' --secure-domain'],
                    ['do' => 'Activa la redireccion permanente a https en Hosting y DNS > Ajustes de hosting.'],
                ],
                'plesk bin subscription --list >/dev/null && plesk bin certificate --list -domain DOMINIO',
                'Emitir un certificado para un dominio que todavia apunta a otro servidor falla y consume el '
                . 'cupo de intentos de Let\'s Encrypt: comprueba primero el DNS.',
                'https://docs.plesk.com/es-ES/obsidian/administrator-guide/73607/'
            ));
    }

    return ['domains' => $domains, 'findings' => $findings];
}

/** Certificados instalados y su caducidad. */
function collect_certificates(): array
{
    $root = plesk_root();
    $certs = [];
    $files = $root ? (glob($root . '/var/certificates/*') ?: []) : [];

    foreach ($files as $file) {
        if (!is_file($file)) {
            continue;
        }
        $pem = (string) slurp($file, 262144);
        if (!str_contains($pem, 'BEGIN CERTIFICATE')) {
            continue;
        }
        $info = @openssl_x509_parse($pem);
        if (!$info || !isset($info['validTo_time_t'])) {
            continue;
        }
        $cn  = $info['subject']['CN'] ?? basename($file);
        $san = [];
        if (isset($info['extensions']['subjectAltName'])) {
            foreach (explode(',', $info['extensions']['subjectAltName']) as $s) {
                $s = trim($s);
                if (str_starts_with($s, 'DNS:')) {
                    $san[] = substr($s, 4);
                }
            }
        }
        $daysLeft = (int) floor(($info['validTo_time_t'] - time()) / 86400);
        $key = $cn . '|' . $info['validTo_time_t'];
        $certs[$key] = [
            'cn'        => $cn,
            'san'       => array_slice(array_unique($san), 0, 12),
            'issuer'    => $info['issuer']['O'] ?? ($info['issuer']['CN'] ?? ''),
            'valid_to'  => $info['validTo_time_t'],
            'days_left' => $daysLeft,
            'expired'   => $daysLeft < 0,
        ];
    }

    $certs = array_values($certs);
    usort($certs, fn($a, $b) => $a['days_left'] <=> $b['days_left']);

    $findings = [];
    $expired  = array_filter($certs, fn($c) => $c['expired']);
    $soon     = array_filter($certs, fn($c) => !$c['expired'] && $c['days_left'] <= 14);

    if ($expired) {
        $findings[] = finding('ssl.expired', SEV_CRIT,
            count($expired) . ' certificado(s) caducado(s)',
            implode(', ', array_slice(array_column($expired, 'cn'), 0, 6)),
            'Renovar con Let\'s Encrypt o SSL It!',
            guide(
                'Un certificado caducado hace que el navegador muestre una pantalla de advertencia a pantalla '
                . 'completa: para el visitante equivale a que el sitio este caido. Si es el del correo, los '
                . 'clientes dejan de poder enviar.',
                [
                    ['do' => 'Mira cual es y desde cuando',
                     'cmd' => 'plesk bin certificate --list -admin; echo | openssl s_client -connect DOMINIO:443 -servername DOMINIO 2>/dev/null | openssl x509 -noout -subject -dates'],
                    ['do' => 'Si es de Let\'s Encrypt, vuelve a emitirlo',
                     'cmd' => 'plesk bin extension --exec letsencrypt cli.php -d DOMINIO -d www.DOMINIO -m admin@DOMINIO'],
                    ['do' => 'Comprueba por que no se renovo solo: casi siempre el dominio dejo de resolver aqui '
                           . 'o la validacion por fichero quedo bloqueada por una redireccion',
                     'cmd' => 'plesk log letsencrypt 2>/dev/null | tail -40'],
                    ['do' => 'Repasa que la tarea de renovacion sigue programada',
                     'cmd' => 'systemctl list-timers | grep -i letsencrypt'],
                ],
                'echo | openssl s_client -connect DOMINIO:443 -servername DOMINIO 2>/dev/null | openssl x509 -noout -dates'
            ));
    }
    if ($soon) {
        $findings[] = finding('ssl.soon', SEV_WARN,
            count($soon) . ' certificado(s) caducan en 14 dias o menos',
            implode(', ', array_map(fn($c) => "{$c['cn']} ({$c['days_left']}d)", array_slice($soon, 0, 6))),
            'Comprobar la renovacion automatica',
            guide(
                'Let\'s Encrypt renueva a los 60 dias de vida, asi que quedar por debajo de 14 significa que la '
                . 'renovacion automatica ya ha fallado varias veces sin que nadie se entere.',
                [
                    ['do' => 'Mira el registro de la extension para ver el motivo del fallo',
                     'cmd' => 'plesk log letsencrypt 2>/dev/null | tail -40'],
                    ['do' => 'Comprueba que el dominio sigue resolviendo a este servidor',
                     'cmd' => 'dig +short A DOMINIO'],
                    ['do' => 'Comprueba que la ruta de validacion no esta redirigida ni bloqueada',
                     'cmd' => 'curl -sI http://DOMINIO/.well-known/acme-challenge/prueba | head -3'],
                    ['do' => 'Fuerza la renovacion una vez resuelto lo anterior',
                     'cmd' => 'plesk bin extension --exec letsencrypt cli.php -d DOMINIO -m admin@DOMINIO'],
                ],
                'echo | openssl s_client -connect DOMINIO:443 -servername DOMINIO 2>/dev/null | openssl x509 -noout -enddate'
            ));
    }

    return ['certificates' => $certs, 'findings' => $findings];
}

/**
 * Versiones de PHP disponibles y cuales estan fuera de soporte.
 * Las fechas son el fin de soporte de seguridad segun php.net.
 */
function collect_php(): array
{
    $eol = [
        '5.6' => '2018-12-31', '7.0' => '2019-01-10', '7.1' => '2019-12-01',
        '7.2' => '2020-11-30', '7.3' => '2021-12-06', '7.4' => '2022-11-28',
        '8.0' => '2023-11-26', '8.1' => '2025-12-31', '8.2' => '2026-12-31',
        '8.3' => '2027-12-31', '8.4' => '2028-12-31', '8.5' => '2029-12-31',
    ];

    $bin = plesk_bin();
    $versions = [];

    if ($bin !== null) {
        $out = run([$bin, 'bin', 'php_handler', '--list'], 25)['out'];
        foreach (explode("\n", $out) as $line) {
            $f = preg_split('/\s{2,}/', trim($line));
            if (count($f) < 5 || !preg_match('/^\d+\.\d+/', $f[2] ?? '')) {
                continue;
            }
            $v = $f[3] ?? '';
            if ($v === '' || isset($versions[$v])) {
                continue;
            }
            $versions[$v] = ['version' => $v, 'full' => $f[2], 'status' => trim((string) end($f))];
        }
    }

    $now  = time();
    $out  = [];
    $dead = [];
    $near = [];
    foreach ($versions as $v => $info) {
        $eolDate = $eol[$v] ?? null;
        $eolTs   = $eolDate ? strtotime($eolDate . ' 23:59:59') : null;
        $isEol   = $eolTs !== null && $now > $eolTs;
        $daysTo  = $eolTs !== null ? (int) floor(($eolTs - $now) / 86400) : null;
        $info['eol_date']  = $eolDate;
        $info['eol']       = $isEol;
        $info['eol_days']  = $daysTo;
        $out[] = $info;
        if ($isEol) {
            $dead[] = $v;
        } elseif ($daysTo !== null && $daysTo <= 120) {
            $near[] = "{$v} ({$daysTo}d)";
        }
    }
    usort($out, fn($a, $b) => vnum($a['version']) <=> vnum($b['version']));

    $findings = [];
    if ($dead) {
        $findings[] = finding('php.eol', SEV_CRIT, 'Versiones de PHP sin soporte de seguridad',
            'PHP ' . implode(', ', $dead) . ' ya no recibe parches',
            'Migrar los dominios afectados a una version soportada y retirar el handler',
            guide(
                'Una version sin soporte no recibe correcciones aunque se publique un fallo grave. Mientras haya '
                . 'un solo sitio usandola, ese sitio es la via de entrada mas facil al servidor.',
                [
                    ['do' => 'Averigua que dominios la estan usando',
                     'cmd' => 'plesk db -Ne "SELECT d.name, h.php_handler_id FROM domains d JOIN hosting h ON h.dom_id=d.id ORDER BY h.php_handler_id"'],
                    ['do' => 'Avisa al responsable de cada sitio: subir de version puede requerir tocar el codigo.'],
                    ['do' => 'Cambia el manejador de un dominio a una version con soporte',
                     'cmd' => 'plesk bin domain --update DOMINIO -php_handler_id plesk-php84-fpm'],
                    ['do' => 'Cuando no quede nadie, retira el paquete para que no vuelva a usarse',
                     'cmd' => 'plesk installer --select-release-current --remove-component php8.1'],
                ],
                'plesk db -Ne "SELECT DISTINCT php_handler_id FROM hosting"',
                'Cambiar de version de PHP puede romper un sitio antiguo. Hazlo dominio a dominio y con una copia '
                . 'de seguridad, no en bloque.'
            ));
    }
    if ($near) {
        $findings[] = finding('php.near_eol', SEV_WARN, 'Versiones de PHP proximas al fin de soporte',
            'PHP ' . implode(', ', $near), 'Planificar la migracion',
            guide(
                'Todavia recibe parches, pero la fecha esta puesta. Migrar con tiempo es un tramite; migrar el '
                . 'dia que aparece un fallo critico es una urgencia.',
                [
                    ['do' => 'Lista que dominios dependen de esas versiones',
                     'cmd' => 'plesk db -Ne "SELECT d.name, h.php_handler_id FROM domains d JOIN hosting h ON h.dom_id=d.id ORDER BY h.php_handler_id"'],
                    ['do' => 'Instala la version nueva para poder probar sin quitar la antigua',
                     'cmd' => 'plesk installer --select-release-current --install-component php8.4'],
                    ['do' => 'Prueba sitio a sitio y ve cambiando el manejador',
                     'cmd' => 'plesk bin domain --update DOMINIO -php_handler_id plesk-php84-fpm'],
                ],
                'plesk db -Ne "SELECT DISTINCT php_handler_id FROM hosting"'
            ));
    }

    return ['versions' => $out, 'findings' => $findings];
}

/** Productos de seguridad de Plesk: Imunify, Sophos, ModSecurity, Fail2Ban, Firewall. */
function collect_security_products(): array
{
    $bin  = plesk_bin();
    $prod = [];
    $findings = [];

    $extList = $bin ? run([$bin, 'bin', 'extension', '--list'], 25)['out'] : '';
    $ext = [];
    foreach (explode("\n", $extList) as $line) {
        if (preg_match('/^(\S+)\s+-\s+(.*)$/', trim($line), $m)) {
            $ext[$m[1]] = trim($m[2]);
        }
    }

    // ModSecurity
    $modsec = ['installed' => false, 'enabled' => false, 'ruleset' => ''];
    $apacheMods = sh("apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null");
    if (str_contains($apacheMods, 'security2_module')) {
        $modsec['installed'] = true;
        $engine = sh("grep -rhiE '^\\s*SecRuleEngine' /etc/apache2/ /etc/httpd/ 2>/dev/null | head -1");
        $modsec['enabled'] = (bool) preg_match('/SecRuleEngine\s+(On|DetectionOnly)/i', $engine);
        $modsec['mode']    = match1('/SecRuleEngine\s+(\w+)/i', $engine) ?? '';
        $modsec['ruleset'] = trim((string) ($bin ? run([$bin, 'db', '-Ne', "SELECT val FROM misc WHERE param='modsecurity_ruleset'"], 15)['out'] : ''));
    }
    $prod['modsecurity'] = $modsec;
    if (!$modsec['installed']) {
        $findings[] = finding('sec.modsec', SEV_WARN, 'ModSecurity no instalado',
            'Sin cortafuegos de aplicacion web delante de los sitios',
            'Activar en Herramientas y configuracion > Firewall de aplicaciones web',
            guide(
                'Es el filtro que para inyecciones SQL, subidas de shells y exploits conocidos de WordPress antes '
                . 'de que lleguen al codigo del sitio. Sin el, la unica defensa es que cada sitio este al dia.',
                [
                    ['do' => 'Instala el componente',
                     'cmd' => 'plesk installer --select-release-current --install-component modsecurity'],
                    ['do' => 'En Herramientas y configuracion > Firewall de aplicaciones web, elige un conjunto de '
                           . 'reglas (OWASP o Comodo) y ponlo primero en modo solo deteccion.'],
                    ['do' => 'Revisa unos dias los falsos positivos antes de pasar a bloqueo',
                     'cmd' => 'tail -100 /var/log/modsec_audit.log 2>/dev/null'],
                    ['do' => 'Cuando este limpio, pasa el motor a activo.'],
                ],
                'plesk bin server_pref --show-web-app-firewall 2>/dev/null || grep -r SecRuleEngine /etc/nginx/modsecurity.conf 2>/dev/null',
                'Activar reglas en modo bloqueo de golpe suele tirar formularios y paneles de administracion '
                . 'legitimos: pasa siempre por la fase de solo deteccion.'
            ));
    } elseif (!$modsec['enabled']) {
        $findings[] = finding('sec.modsec.off', SEV_WARN, 'ModSecurity instalado pero no activo',
            'Modo: ' . ($modsec['mode'] ?: 'desconocido'), 'Poner SecRuleEngine en On',
            guide(
                'Esta cargado pero no bloquea nada: en modo desactivado ni siquiera anota lo que habria parado. '
                . 'El coste ya lo estas pagando, aprovecha la proteccion.',
                [
                    ['do' => 'Comprueba el modo actual',
                     'cmd' => 'grep -r "SecRuleEngine" /etc/nginx/modsecurity.conf /etc/apache2/conf.d/security2.conf 2>/dev/null'],
                    ['do' => 'Ponlo en solo deteccion unos dias desde Herramientas y configuracion > Firewall de '
                           . 'aplicaciones web y revisa los avisos.'],
                    ['do' => 'Mira que reglas saltarian con el trafico real',
                     'cmd' => 'tail -100 /var/log/modsec_audit.log 2>/dev/null'],
                    ['do' => 'Pasa a activo cuando no queden falsos positivos, y recarga el servidor web',
                     'cmd' => 'plesk sbin httpdmng --reconfigure-all'],
                ],
                'grep -r "SecRuleEngine" /etc/nginx/modsecurity.conf 2>/dev/null'
            ));
    }

    // Imunify360 / ImunifyAV
    $imunify = ['installed' => false];
    if (have('imunify360-agent') || is_dir('/opt/imunify360')) {
        $imunify['installed'] = true;
        $json = sh("imunify360-agent version --json 2>/dev/null", 30);
        $d = json_decode($json, true);
        $imunify['version'] = is_array($d) ? ($d['items']['version'] ?? ($d['version'] ?? '')) : '';
        $st = sh("systemctl is-active imunify360 2>/dev/null");
        $imunify['active'] = trim($st) === 'active';
        // Incidentes recientes si el agente lo permite
        $inc = json_decode(sh("imunify360-agent incidents list --limit 1 --json 2>/dev/null", 30), true);
        $imunify['incidents_available'] = is_array($inc);
    } elseif (isset($ext['imunify360'])) {
        $imunify['extension_present'] = true;
    }
    $prod['imunify'] = $imunify;

    // Antivirus Sophos
    $sophos = ['installed' => isset($ext['sophos-av']) || is_dir('/opt/sophos-av')];
    if ($sophos['installed']) {
        $sophos['active'] = trim(sh("systemctl is-active sav-protect 2>/dev/null || systemctl is-active plesk-sophos-av 2>/dev/null")) === 'active';
        if (!$sophos['active']) {
            $findings[] = finding('sec.sophos', SEV_INFO, 'Sophos Anti-Virus instalado pero inactivo',
                'El paquete esta presente y recibe actualizaciones, pero el servicio no corre',
                'Arrancarlo o desinstalarlo para no mantener software sin uso',
                guide(
                    'Software instalado que no se usa sigue teniendo sus propias vulnerabilidades y consume '
                    . 'mantenimiento. O lo pones a trabajar o lo quitas: dejarlo a medias es lo peor de ambos mundos.',
                    [
                        ['do' => 'Mira si esta parado a proposito o ha fallado',
                         'cmd' => 'systemctl status sav-protect plesk-sophos-av --no-pager -l 2>/dev/null | head -30'],
                        ['do' => 'Si quieres analisis de correo, arrancalo y dejalo habilitado',
                         'cmd' => 'systemctl enable --now sav-protect'],
                        ['do' => 'Si no lo usas, desinstala la extension para no arrastrarla',
                         'cmd' => 'plesk bin extension --uninstall sophos-av'],
                    ],
                    'systemctl is-active sav-protect 2>/dev/null || systemctl is-active plesk-sophos-av'
                ));
        }
    }
    $prod['sophos'] = $sophos;

    // Extension de firewall de Plesk
    $prod['plesk_firewall'] = ['extension' => isset($ext['firewall'])];

    $prod['extensions'] = $ext;
    return ['products' => $prod, 'findings' => $findings];
}
