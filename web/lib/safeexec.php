<?php
/**
 * Centinela - ejecucion controlada de herramientas de red (looking glass).
 *
 * Reglas que sostienen la seguridad de este fichero:
 *   1. La lista de comandos es cerrada; el usuario elige una clave, no un binario.
 *   2. Nunca se invoca un shell: proc_open recibe un array de argumentos.
 *   3. El destino se valida y se resuelve, y se rechaza si apunta a red interna.
 *   4. Todo comando tiene timeout y la salida se trunca.
 */

declare(strict_types=1);

/**
 * Catalogo de herramientas.
 *
 * 'group' agrupa en la interfaz; 'icon' es la clave del icono SVG.
 * El usuario elige una clave de esta lista: nunca escribe un binario.
 */
function lg_commands(): array
{
    return [
        'ping' => [
            'label' => 'Ping',
            'group' => 'Conectividad',
            'icon'  => 'pulse',
            'desc'  => 'Latencia y perdida de paquetes hasta el destino',
            'hint'  => '1.1.1.1 o ejemplo.com',
            'build' => fn(string $ip) => [bin_path('ping'), '-c', '4', '-W', '2', '-n', '--', $ip],
            'timeout' => 15,
        ],
        'traceroute' => [
            'label' => 'Traceroute',
            'group' => 'Conectividad',
            'icon'  => 'route',
            'desc'  => 'Ruta de red salto a salto, con latencia por tramo',
            'hint'  => '1.1.1.1 o ejemplo.com',
            'build' => function (string $ip) {
                if (bin_path('mtr')) {
                    return [bin_path('mtr'), '-r', '-c', '3', '-n', '--', $ip];
                }
                return [bin_path('traceroute'), '-n', '-w', '2', '-q', '1', '-m', '20', $ip];
            },
            'timeout' => 45,
        ],
        'geoping' => [
            'label' => 'Latencia global',
            'group' => 'Conectividad',
            'icon'  => 'globe2',
            'desc'  => 'Ping desde sondas reales en varios continentes: detecta enrutado que falla por region',
            'hint'  => '1.1.1.1 o ejemplo.com',
            'timeout' => 35,
            'handler' => 'lg_geoping',
            'accepts_hostname' => true,
        ],

        'portscan' => [
            'label' => 'Puertos abiertos',
            'group' => 'Conectividad',
            'icon'  => 'grid',
            'desc'  => 'Comprueba 21 puertos habituales y senala los de riesgo',
            'hint'  => 'ejemplo.com',
            'timeout' => 20,
            'handler' => 'lg_portscan',
        ],
        'port' => [
            'label' => 'Puerto concreto',
            'group' => 'Conectividad',
            'icon'  => 'plug',
            'desc'  => 'Comprueba si un puerto TCP acepta conexiones',
            'hint'  => 'ejemplo.com',
            'field' => 'port',
            'timeout' => 10,
            'handler' => 'lg_port',
        ],

        'mtu' => [
            'label' => 'MTU de la ruta',
            'group' => 'Conectividad',
            'icon'  => 'ruler',
            'desc'  => 'Busca el tamano maximo de paquete sin fragmentar hasta el destino',
            'hint'  => '1.1.1.1 o ejemplo.com',
            'timeout' => 25,
            'handler' => 'lg_mtu',
        ],

        'dns' => [
            'label' => 'Consulta DNS',
            'group' => 'Nombres',
            'icon'  => 'dns',
            'desc'  => 'Registros publicos del dominio, por tipo',
            'hint'  => 'ejemplo.com',
            'field' => 'type',
            'build' => fn(string $t, array $o) => [bin_path('dig'), '+noall', '+answer', '+authority',
                                                   '+time=3', '+tries=2', $t, $o['type'] ?? 'A'],
            'timeout' => 15,
            'accepts_hostname' => true,
        ],
        'rdns' => [
            'label' => 'DNS inverso',
            'group' => 'Nombres',
            'icon'  => 'swap',
            'desc'  => 'Registro PTR y validacion directa-inversa',
            'hint'  => '8.8.8.8',
            'timeout' => 20,
            'handler' => 'lg_rdns',
        ],
        'rdap' => [
            'label' => 'RDAP / WHOIS',
            'group' => 'Nombres',
            'icon'  => 'book',
            'desc'  => 'Titular, registrador, fechas y contacto de abuso',
            'hint'  => 'ejemplo.com o 8.8.8.8',
            'timeout' => 20,
            'handler' => 'lg_rdap',
        ],
        'asn' => [
            'label' => 'ASN y enrutado',
            'group' => 'Nombres',
            'icon'  => 'network',
            'desc'  => 'Sistema autonomo, prefijo anunciado y pais',
            'hint'  => '8.8.8.8 o ejemplo.com',
            'timeout' => 15,
            'handler' => 'lg_asn',
        ],

        'asnmap' => [
            'label' => 'Mapa BGP',
            'group' => 'Nombres',
            'icon'  => 'globe',
            'desc'  => 'Donde anuncia sus rutas un sistema autonomo, sobre un mapa',
            'hint'  => 'AS3352, 8.8.8.8 o ejemplo.com',
            'timeout' => 30,
            'handler' => 'lg_asnmap',
            'accepts_asn' => true,
        ],

        'reputation' => [
            'label' => 'Reputacion IP',
            'group' => 'Seguridad',
            'icon'  => 'radar',
            'desc'  => 'Historial de ataques, botnets, redes secuestradas y a quien reportar',
            'hint'  => '94.154.43.56 o ejemplo.com',
            'timeout' => 30,
            'handler' => 'lg_reputation',
        ],

        'dnsprop' => [
            'label' => 'Propagacion DNS',
            'group' => 'Nombres',
            'icon'  => 'broadcast',
            'desc'  => 'Consulta el mismo registro en 8 resolutores publicos y detecta discrepancias',
            'hint'  => 'ejemplo.com',
            'field' => 'type',
            'timeout' => 20,
            'handler' => 'lg_dnsprop',
            'accepts_hostname' => true,
        ],

        'tls' => [
            'label' => 'Certificado TLS',
            'group' => 'Seguridad',
            'icon'  => 'lock',
            'desc'  => 'Cadena, caducidad, protocolo y cifrado negociado',
            'hint'  => 'ejemplo.com',
            'field' => 'port',
            'timeout' => 20,
            'handler' => 'lg_tls',
        ],
        'headers' => [
            'label' => 'Cabeceras HTTP',
            'group' => 'Seguridad',
            'icon'  => 'shield',
            'desc'  => 'Cabeceras de seguridad valoradas con una nota',
            'hint'  => 'ejemplo.com',
            'timeout' => 20,
            'handler' => 'lg_headers',
        ],
        'dnssec' => [
            'label' => 'DNSSEC',
            'group' => 'Seguridad',
            'icon'  => 'keychain',
            'desc'  => 'Valida la cadena de firmas y senala donde se rompe',
            'hint'  => 'cloudflare.com',
            'timeout' => 25,
            'handler' => 'lg_dnssec',
            'accepts_hostname' => true,
        ],
        'crt' => [
            'label' => 'Certificados emitidos',
            'group' => 'Seguridad',
            'icon'  => 'stamp',
            'desc'  => 'Historial de Certificate Transparency: todo cert emitido y subdominios que revela',
            'hint'  => 'ejemplo.com',
            'timeout' => 25,
            'handler' => 'lg_crt',
            'accepts_hostname' => true,
        ],
        'smtp' => [
            'label' => 'Entrega SMTP',
            'group' => 'Seguridad',
            'icon'  => 'envelope',
            'desc'  => 'Conecta a cada MX: saludo, STARTTLS, certificado y DANE',
            'hint'  => 'ejemplo.com',
            'timeout' => 30,
            'handler' => 'lg_smtp',
            'accepts_hostname' => true,
        ],
        'fingerprint' => [
            'label' => 'Analisis de servidor',
            'group' => 'Seguridad',
            'icon'  => 'fingerprint',
            'desc'  => 'Identifica servidor web, panel, CMS y version, y busca CVE conocidos',
            'hint'  => 'ejemplo.com',
            'timeout' => 30,
            'handler' => 'lg_fingerprint',
        ],
        'rbl' => [
            'label' => 'Listas negras',
            'group' => 'Seguridad',
            'icon'  => 'ban',
            'desc'  => 'Reputacion de la IP en 10 listas antispam',
            'hint'  => '8.8.8.8 o ejemplo.com',
            'timeout' => 30,
            'handler' => 'lg_rbl',
        ],
        'mail' => [
            'label' => 'Correo del dominio',
            'group' => 'Seguridad',
            'icon'  => 'mail',
            'desc'  => 'MX, SPF, DKIM y DMARC con diagnostico',
            'hint'  => 'ejemplo.com',
            'timeout' => 25,
            'handler' => 'lg_mail',
        ],
    ];
}

/**
 * Primera captura de un patron, o null.
 *
 * Hay una funcion equivalente en la libreria del colector, pero la capa web no
 * la carga a proposito: solo incluye lo imprescindible para responder.
 */
if (!function_exists('match1')) {
    function match1(string $pattern, ?string $subject): ?string
    {
        if ($subject === null) {
            return null;
        }
        return preg_match($pattern, $subject, $m) ? $m[1] : null;
    }
}

/**
 * Ruta absoluta de una herramienta permitida, o null si no esta.
 *
 * No se puede usar is_executable(): Plesk aplica open_basedir al dominio y
 * eso hace que las comprobaciones sobre /usr/bin devuelvan siempre falso.
 * Por eso el instalador detecta las rutas (donde no hay restriccion) y las
 * deja en la configuracion; aqui solo se consulta esa lista.
 */
function bin_path(string $name): ?string
{
    static $allowed = ['ping', 'mtr', 'traceroute', 'dig', 'host'];
    static $cache = [];

    if (!in_array($name, $allowed, true)) {
        return null;
    }
    if (array_key_exists($name, $cache)) {
        return $cache[$name];
    }

    $cfg = load_config();
    $configured = $cfg['lg']['bin'][$name] ?? null;
    if (is_string($configured) && $configured !== '') {
        // La ruta viene de la instalacion, pero se valida igualmente
        return $cache[$name] = (preg_match('#^/[a-zA-Z0-9/_.-]+$#', $configured)
            && basename($configured) === $name) ? $configured : null;
    }

    // Sin configuracion: probamos las ubicaciones habituales. Si open_basedir
    // impide comprobarlo, devolvemos la primera y que decida proc_open.
    foreach (['/usr/bin/', '/bin/', '/usr/sbin/', '/sbin/'] as $d) {
        if (@is_executable($d . $name)) {
            return $cache[$name] = $d . $name;
        }
    }
    return $cache[$name] = @file_exists('/usr/bin/' . $name) ? '/usr/bin/' . $name : '/usr/bin/' . $name;
}

/** Valida la sintaxis de un destino (IP o nombre de host). */
function lg_valid_target(string $t): bool
{
    if (strlen($t) < 1 || strlen($t) > 253) {
        return false;
    }
    if (filter_var($t, FILTER_VALIDATE_IP)) {
        return true;
    }
    // Nombre de dominio: etiquetas alfanumericas separadas por puntos
    return (bool) preg_match('/^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$/', $t);
}

/**
 * ¿La IP pertenece a un rango que no debe alcanzarse desde el looking glass?
 * Evita que un tercero use la herramienta para sondear la red interna.
 */
function lg_is_private_ip(string $ip): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return true;
    }
    // Rechaza privadas y reservadas segun los rangos de PHP
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return true;
    }
    // Refuerzo explicito de rangos que PHP no siempre marca
    $extra = [
        '0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10',
        '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24',
        '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10', '::/128',
    ];
    foreach ($extra as $cidr) {
        if (ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * Resuelve un destino a una IP publica utilizable.
 *
 * @return array{ok:bool, ip:string, error:string, resolved:array}
 */
function lg_resolve(string $target): array
{
    if (filter_var($target, FILTER_VALIDATE_IP)) {
        if (lg_is_private_ip($target)) {
            return ['ok' => false, 'ip' => '', 'error' => 'Las direcciones privadas o reservadas no estan permitidas.', 'resolved' => []];
        }
        return ['ok' => true, 'ip' => $target, 'error' => '', 'resolved' => [$target]];
    }

    $ips = [];
    foreach (['A' => DNS_A, 'AAAA' => DNS_AAAA] as $rr) {
        $recs = @dns_get_record($target, $rr) ?: [];
        foreach ($recs as $r) {
            if (!empty($r['ip']))   { $ips[] = $r['ip']; }
            if (!empty($r['ipv6'])) { $ips[] = $r['ipv6']; }
        }
    }
    $ips = array_values(array_unique($ips));

    if (!$ips) {
        return ['ok' => false, 'ip' => '', 'error' => 'El nombre no resuelve a ninguna direccion.', 'resolved' => []];
    }
    // Si CUALQUIERA de las respuestas es interna, rechazamos: evita que un
    // dominio con un registro apuntando a 127.0.0.1 sirva de rodeo.
    foreach ($ips as $ip) {
        if (lg_is_private_ip($ip)) {
            return ['ok' => false, 'ip' => '', 'error' => 'El nombre resuelve a una direccion interna.', 'resolved' => $ips];
        }
    }
    return ['ok' => true, 'ip' => $ips[0], 'error' => '', 'resolved' => $ips];
}

/**
 * Ejecuta una consulta del looking glass.
 *
 * @return array{ok:bool, output:string, error:string, meta:array}
 */
function lg_run(string $cmdKey, string $target, array $options = []): array
{
    $cmds = lg_commands();
    if (!isset($cmds[$cmdKey])) {
        return ['ok' => false, 'output' => '', 'error' => 'Comando no permitido.', 'blocks' => [], 'meta' => []];
    }
    $spec = $cmds[$cmdKey];

    $target = trim($target);
    // Algunas herramientas aceptan ademas un numero de sistema autonomo
    $esAsn = !empty($spec['accepts_asn']) && preg_match('/^(?:as)?\d{1,10}$/i', $target);
    if (!$esAsn && !lg_valid_target($target)) {
        return ['ok' => false, 'output' => '', 'error' => 'Destino invalido. Indica una IP, un dominio' . (!empty($spec['accepts_asn']) ? ' o un ASN (AS3352)' : '') . '.', 'blocks' => [], 'meta' => []];
    }

    // Los comandos con manejador propio se encargan de su validacion
    if (isset($spec['handler'])) {
        $r = ($spec['handler'])($target, $options);
        return $r + ['blocks' => [], 'meta' => []];
    }

    // Las consultas DNS operan sobre el nombre, no sobre la IP resuelta
    if (!empty($spec['accepts_hostname'])) {
        $arg = $target;
        $meta = [];
    } else {
        $res = lg_resolve($target);
        if (!$res['ok']) {
            return ['ok' => false, 'output' => '', 'error' => $res['error'], 'meta' => []];
        }
        $arg  = $res['ip'];
        $meta = ['resolved' => $res['resolved']];
    }

    $cmd = ($spec['build'])($arg, $options);
    if (!$cmd || in_array(null, $cmd, true)) {
        return ['ok' => false, 'output' => '', 'error' => 'La herramienta no esta disponible en este servidor.', 'meta' => []];
    }

    $out = lg_proc($cmd, (int) ($spec['timeout'] ?? 15));
    return [
        'ok'     => true,
        'output' => $out,
        'error'  => '',
        'blocks' => lg_summarize($cmdKey, $out),
        'meta'   => $meta + ['command' => basename($cmd[0]), 'target' => $arg],
    ];
}

/** Lanza el proceso y recoge la salida con limite de tiempo y tamano. */
function lg_proc(array $cmd, int $timeout): string
{
    $desc  = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $env   = ['PATH' => '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL' => 'C'];
    $proc  = @proc_open($cmd, $desc, $pipes, '/tmp', $env);
    if (!is_resource($proc)) {
        return 'No se pudo ejecutar la herramienta.';
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $out = '';
    $deadline = microtime(true) + $timeout;
    while (true) {
        $out .= (string) stream_get_contents($pipes[1]);
        $out .= (string) stream_get_contents($pipes[2]);
        if (strlen($out) > 65536) {
            $out = substr($out, 0, 65536) . "\n[salida truncada]";
            proc_terminate($proc, SIGKILL);
            break;
        }
        $st = proc_get_status($proc);
        if (!$st['running']) {
            break;
        }
        if (microtime(true) > $deadline) {
            proc_terminate($proc, SIGKILL);
            $out .= "\n[tiempo de espera agotado tras {$timeout}s]";
            break;
        }
        usleep(30000);
    }
    $out .= (string) stream_get_contents($pipes[1]);
    $out .= (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    return trim($out) !== '' ? $out : 'Sin salida.';
}

/** Manejador: consulta de ASN via Team Cymru. */
function lg_asn(string $target, array $options): array
{
    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip = $res['ip'];

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $q = implode('.', array_reverse(explode('.', $ip))) . '.origin.asn.cymru.com';
    } else {
        $hex = bin2hex((string) inet_pton($ip));
        $q = implode('.', array_reverse(str_split($hex))) . '.origin6.asn.cymru.com';
    }

    $dig = bin_path('dig');
    if ($dig === null) {
        return lg_err('La herramienta dig no esta disponible en este servidor.');
    }

    $txt = trim(lg_proc([$dig, '+short', '+time=3', '+tries=2', $q, 'TXT'], 10));
    if ($txt === '' || $txt === 'Sin salida.') {
        return lg_ok("Sin datos de enrutado para {$ip}.",
            [lg_block('rows', 'Enrutado', [
                lg_row('Direccion', $ip),
                lg_row('Anuncio BGP', 'no encontrado', 'warn',
                    'la direccion podria no estar anunciada en la tabla global'),
            ], 'warn')],
            ['target' => $ip]);
    }

    $first = trim(explode("\n", $txt)[0], '" \t');
    $p = array_map('trim', explode('|', $first));
    $asnRaw = $p[0] ?? '';
    $asnNum = trim(explode(' ', $asnRaw)[0]);

    $org = '';
    if ($asnNum !== '' && ctype_digit($asnNum)) {
        $atxt = trim(lg_proc([$dig, '+short', '+time=3', '+tries=2', "AS{$asnNum}.asn.cymru.com", 'TXT'], 10));
        $ap = explode('|', trim($atxt, '" \t'));
        $org = isset($ap[4]) ? trim($ap[4]) : '';
    }

    $rows = [
        lg_row('Direccion', $ip),
        lg_row('Sistema autonomo', $asnNum !== '' ? 'AS' . $asnNum : 'desconocido'),
        lg_row('Operador', $org ?: 'desconocido'),
        lg_row('Prefijo anunciado', $p[1] ?? '—'),
        lg_row('Pais de registro', $p[2] ?? '—'),
        lg_row('Registro regional', strtoupper($p[3] ?? '—')),
    ];
    if (count($res['resolved']) > 1) {
        $rows[] = lg_row('Otras direcciones', implode(', ', array_slice($res['resolved'], 1, 6)));
    }
    // Un prefijo con varios origenes puede indicar multihoming o un secuestro
    if (substr_count($txt, "\n") > 0) {
        $rows[] = lg_row('Origenes multiples', 'si', 'warn',
            'el prefijo se anuncia desde mas de un sistema autonomo');
    }

    $out = "Enrutado de {$ip}\n" . str_repeat('-', 50) . "\n";
    foreach ($rows as $r) {
        $out .= sprintf("%-22s %s\n", $r['k'] . ':', $r['v']);
    }

    return lg_ok(trim($out), [lg_block('rows', 'Enrutado global', $rows)], ['target' => $ip]);
}

/** Manejador: prueba de puerto TCP sin lanzar procesos externos. */
function lg_port(string $target, array $options): array
{
    $port = (int) ($options['port'] ?? 0);
    if ($port < 1 || $port > 65535) {
        return lg_err('Puerto fuera de rango (1-65535).');
    }

    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip = $res['ip'];

    $t0 = microtime(true);
    $errno = 0;
    $errstr = '';
    $host = str_contains($ip, ':') ? "[{$ip}]" : $ip;
    $sock = @stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, 5);
    $ms = round((microtime(true) - $t0) * 1000);

    $open = (bool) $sock;
    $banner = '';
    if ($open) {
        // Algunos servicios se anuncian nada mas conectar
        stream_set_timeout($sock, 2);
        $banner = trim((string) @fread($sock, 200));
        $banner = preg_replace('/[^\x20-\x7E]/', ' ', $banner) ?? '';
        fclose($sock);
    }

    $rows = [
        lg_row('Direccion', $ip),
        lg_row('Puerto', $port . '/tcp'),
        lg_row('Estado', $open ? 'abierto' : 'cerrado o filtrado', $open ? 'good' : 'warn',
            $open ? '' : ($errstr !== '' ? $errstr : 'sin respuesta')),
        lg_row('Tiempo de conexion', $ms . ' ms'),
    ];
    if ($banner !== '') {
        $rows[] = lg_row('Anuncio del servicio', mb_strimwidth($banner, 0, 90, '…'));
    }

    $out = "Puerto {$port}/tcp en {$ip}: " . ($open ? 'ABIERTO' : 'cerrado o filtrado')
        . "\nTiempo: {$ms} ms" . ($banner !== '' ? "\nAnuncio: {$banner}" : '');

    return lg_ok($out, [lg_block('rows', 'Prueba de puerto', $rows, $open ? 'good' : 'warn')], ['target' => $ip]);
}

/**
 * Extrae un resumen legible de la salida de las herramientas de terminal.
 * El texto crudo se conserva siempre; esto solo anade una lectura rapida.
 */
function lg_summarize(string $cmdKey, string $out): array
{
    if ($cmdKey === 'ping') {
        $loss = match1('/(\d+(?:\.\d+)?)% packet loss/', $out);
        $rtt  = null;
        if (preg_match('#rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)#', $out, $m)) {
            $rtt = ['min' => $m[1], 'avg' => $m[2], 'max' => $m[3], 'mdev' => $m[4]];
        }
        if ($loss === null && $rtt === null) {
            return [];
        }
        $lossF = (float) ($loss ?? 100);
        $status = $lossF >= 100 ? 'crit' : ($lossF > 0 ? 'warn' : 'good');

        $rows = [
            lg_row('Perdida de paquetes', ($loss ?? '?') . ' %', $status,
                $lossF >= 100 ? 'el destino no responde' : ($lossF > 0 ? 'la ruta pierde paquetes' : 'sin perdidas')),
        ];
        if ($rtt) {
            $avg = (float) $rtt['avg'];
            $rows[] = lg_row('Latencia media', $rtt['avg'] . ' ms',
                $avg < 50 ? 'good' : ($avg < 150 ? 'warn' : 'crit'),
                $avg < 50 ? 'excelente' : ($avg < 150 ? 'aceptable' : 'alta'));
            $rows[] = lg_row('Minima / maxima', $rtt['min'] . ' — ' . $rtt['max'] . ' ms');
            $rows[] = lg_row('Variacion', $rtt['mdev'] . ' ms',
                (float) $rtt['mdev'] < 10 ? 'good' : 'warn',
                (float) $rtt['mdev'] < 10 ? 'ruta estable' : 'ruta inestable');
        }
        return [lg_block('rows', 'Resumen', $rows, $status)];
    }

    if ($cmdKey === 'traceroute') {
        $hops = 0;
        $lost = 0;
        foreach (explode("\n", $out) as $line) {
            if (preg_match('/^\s*(\d+)\.\|--|\s*(\d+)\s+\S/', $line)) {
                $hops++;
                if (str_contains($line, '???') || preg_match('/\*\s+\*\s+\*/', $line)) {
                    $lost++;
                }
            }
        }
        if ($hops === 0) {
            return [];
        }
        return [lg_block('rows', 'Resumen', [
            lg_row('Saltos hasta el destino', (string) $hops),
            lg_row('Saltos sin respuesta', (string) $lost, $lost > 0 ? 'warn' : 'good',
                $lost > 0 ? 'algunos routers no responden, lo cual es habitual' : ''),
        ])];
    }

    return [];
}
