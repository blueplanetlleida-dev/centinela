<?php
/**
 * Centinela - herramientas avanzadas del looking glass.
 *
 * Todas devuelven la misma forma:
 *   ['ok'=>bool, 'error'=>string, 'output'=>string, 'blocks'=>array, 'meta'=>array]
 *
 * 'blocks' permite que la interfaz pinte tarjetas estructuradas en lugar de
 * texto plano. 'output' se mantiene siempre como salida cruda de respaldo.
 *
 * Seguridad: cualquier herramienta que abra una conexion resuelve primero el
 * destino, comprueba que TODAS sus direcciones son publicas y despues conecta
 * contra la IP validada, no contra el nombre. Asi un dominio no puede
 * reapuntar a la red interna entre la comprobacion y la conexion.
 */

declare(strict_types=1);

/** Bloque estructurado para la interfaz. */
function lg_block(string $type, string $title, array $data, string $status = ''): array
{
    return ['type' => $type, 'title' => $title, 'status' => $status, 'data' => $data];
}

/** Fila de par clave/valor con estado opcional. */
function lg_row(string $k, $v, string $status = '', string $note = ''): array
{
    return ['k' => $k, 'v' => $v, 'status' => $status, 'note' => $note];
}

function lg_ok(string $output, array $blocks = [], array $meta = []): array
{
    return ['ok' => true, 'error' => '', 'output' => $output, 'blocks' => $blocks, 'meta' => $meta];
}

function lg_err(string $error): array
{
    return ['ok' => false, 'error' => $error, 'output' => '', 'blocks' => [], 'meta' => []];
}

// ---------------------------------------------------------------------------
// Conexiones con destino fijado
// ---------------------------------------------------------------------------

/**
 * Abre un socket contra una IP ya validada, presentando el nombre original
 * para SNI y verificacion de certificado.
 *
 * @return resource|null
 */
function lg_connect(string $ip, int $port, ?string $sni, bool $tls, float $timeout, array &$meta = [])
{
    $host = str_contains($ip, ':') ? "[{$ip}]" : $ip;
    $ctx  = stream_context_create([
        'ssl' => [
            'peer_name'         => $sni ?? $ip,
            'SNI_enabled'       => $sni !== null,
            // El objetivo es inspeccionar, no confiar: un certificado invalido
            // es justo lo que queremos poder mostrar.
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
        ],
    ]);

    $errno = 0;
    $errstr = '';
    $scheme = $tls ? 'ssl' : 'tcp';
    $sock = @stream_socket_client(
        "{$scheme}://{$host}:{$port}",
        $errno,
        $errstr,
        $timeout,
        STREAM_CLIENT_CONNECT,
        $ctx
    );

    if (!$sock) {
        $meta['error'] = $errstr !== '' ? $errstr : "no se pudo conectar (codigo {$errno})";
        return null;
    }
    stream_set_timeout($sock, (int) ceil($timeout));
    return $sock;
}

// ---------------------------------------------------------------------------
// Inspector TLS
// ---------------------------------------------------------------------------

function lg_tls(string $target, array $options): array
{
    $port = (int) ($options['port'] ?? 443);
    if ($port < 1 || $port > 65535) {
        return lg_err('Puerto fuera de rango.');
    }

    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip   = $res['ip'];
    $sni  = filter_var($target, FILTER_VALIDATE_IP) ? null : rtrim($target, '.');

    $meta = [];
    $t0   = microtime(true);
    $sock = lg_connect($ip, $port, $sni, true, 8.0, $meta);
    if ($sock === null) {
        return lg_err('No se pudo establecer TLS con ' . $ip . ':' . $port . ' — ' . ($meta['error'] ?? 'sin respuesta'));
    }
    $handshakeMs = round((microtime(true) - $t0) * 1000);

    $params = stream_context_get_params($sock);
    $certR  = $params['options']['ssl']['peer_certificate'] ?? null;
    $chainR = $params['options']['ssl']['peer_certificate_chain'] ?? [];
    $crypto = stream_get_meta_data($sock)['crypto'] ?? [];
    fclose($sock);

    if ($certR === null) {
        return lg_err('El servidor no presento ningun certificado.');
    }

    $c = openssl_x509_parse($certR);
    if (!$c) {
        return lg_err('No se pudo interpretar el certificado.');
    }

    $now    = time();
    $from   = (int) ($c['validFrom_time_t'] ?? 0);
    $to     = (int) ($c['validTo_time_t'] ?? 0);
    $days   = (int) floor(($to - $now) / 86400);
    $expired = $now > $to;
    $notYet  = $now < $from;

    // Nombres cubiertos
    $san = [];
    foreach (explode(',', (string) ($c['extensions']['subjectAltName'] ?? '')) as $s) {
        $s = trim($s);
        if (str_starts_with($s, 'DNS:')) {
            $san[] = substr($s, 4);
        } elseif (str_starts_with($s, 'IP Address:')) {
            $san[] = trim(substr($s, 11));
        }
    }
    $cn = $c['subject']['CN'] ?? '';
    if ($cn !== '' && !in_array($cn, $san, true)) {
        array_unshift($san, $cn);
    }

    // ¿El certificado cubre el nombre consultado?
    $covers = null;
    if ($sni !== null) {
        $covers = false;
        foreach ($san as $n) {
            $n = strtolower(trim($n));
            $h = strtolower($sni);
            if ($n === $h) { $covers = true; break; }
            if (str_starts_with($n, '*.')) {
                $base = substr($n, 2);
                // El comodin cubre un unico nivel de subdominio
                if (str_ends_with($h, '.' . $base) && substr_count($h, '.') === substr_count($base, '.') + 1) {
                    $covers = true;
                    break;
                }
            }
        }
    }

    $proto  = $crypto['protocol'] ?? 'desconocido';
    $cipher = $crypto['cipher_name'] ?? 'desconocido';
    $bits   = $crypto['cipher_bits'] ?? 0;

    $sigalg = $c['signatureTypeSN'] ?? ($c['signatureTypeLN'] ?? 'desconocido');
    $issuer = $c['issuer']['O'] ?? ($c['issuer']['CN'] ?? 'desconocido');

    // Valoracion del protocolo
    $protoStatus = match (true) {
        str_contains($proto, '1.3') => 'good',
        str_contains($proto, '1.2') => 'good',
        str_contains($proto, '1.1'), str_contains($proto, '1.0') => 'crit',
        default => 'warn',
    };

    $expiryStatus = $expired ? 'crit' : ($days <= 14 ? 'warn' : 'good');
    $expiryNote   = $expired ? 'caducado hace ' . abs($days) . ' dias'
                  : ($notYet ? 'aun no es valido' : "quedan {$days} dias");

    $rows = [
        lg_row('Nombre comun', $cn ?: '—'),
        lg_row('Emisor', $issuer),
        lg_row('Valido desde', $from ? date('d/m/Y H:i', $from) : '—'),
        lg_row('Valido hasta', $to ? date('d/m/Y H:i', $to) : '—', $expiryStatus, $expiryNote),
        lg_row('Algoritmo de firma', $sigalg, str_contains(strtolower($sigalg), 'sha1') ? 'crit' : 'good',
            str_contains(strtolower($sigalg), 'sha1') ? 'SHA-1 esta obsoleto' : ''),
        lg_row('Numero de serie', $c['serialNumberHex'] ?? ($c['serialNumber'] ?? '—')),
    ];
    if ($covers !== null) {
        $rows[] = lg_row('Cubre el nombre consultado', $covers ? 'si' : 'no',
            $covers ? 'good' : 'crit', $covers ? '' : "el certificado no incluye {$sni}");
    }

    $blocks = [
        lg_block('rows', 'Certificado', $rows, $expiryStatus),
        lg_block('rows', 'Conexion', [
            lg_row('Protocolo', $proto, $protoStatus,
                $protoStatus === 'crit' ? 'version obsoleta' : ''),
            lg_row('Cifrado', $cipher),
            lg_row('Fortaleza', $bits ? $bits . ' bits' : '—', $bits >= 128 ? 'good' : 'warn'),
            lg_row('Negociacion', $handshakeMs . ' ms'),
            lg_row('Direccion', $ip . ':' . $port),
        ], $protoStatus),
        lg_block('tags', 'Nombres cubiertos (' . count($san) . ')', array_slice($san, 0, 40)),
    ];

    // Cadena de confianza
    $chain = [];
    foreach ($chainR as $i => $cr) {
        $p = openssl_x509_parse($cr);
        if ($p) {
            $chain[] = lg_row(
                $i === 0 ? 'Servidor' : ($i === count($chainR) - 1 ? 'Raiz' : 'Intermedio ' . $i),
                ($p['subject']['CN'] ?? '?') . '  ←  ' . ($p['issuer']['CN'] ?? '?')
            );
        }
    }
    if ($chain) {
        $blocks[] = lg_block('rows', 'Cadena de certificacion (' . count($chain) . ')', $chain);
    }

    $out = "Certificado de {$target}:{$port}\n"
        . str_repeat('-', 50) . "\n"
        . "CN         : {$cn}\n"
        . "Emisor     : {$issuer}\n"
        . "Valido     : " . date('d/m/Y', $from) . ' — ' . date('d/m/Y', $to) . "  ({$expiryNote})\n"
        . "Protocolo  : {$proto}\n"
        . "Cifrado    : {$cipher} ({$bits} bits)\n"
        . "Nombres    : " . implode(', ', array_slice($san, 0, 15)) . (count($san) > 15 ? ', …' : '');

    return lg_ok($out, $blocks, ['target' => $ip, 'resolved' => $res['resolved']]);
}

// ---------------------------------------------------------------------------
// Cabeceras HTTP y nota de seguridad
// ---------------------------------------------------------------------------

function lg_headers(string $target, array $options): array
{
    if (filter_var($target, FILTER_VALIDATE_IP)) {
        $host = $target;
    } else {
        $host = rtrim($target, '.');
    }

    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }

    $tls  = ($options['scheme'] ?? 'https') !== 'http';
    $port = $tls ? 443 : 80;

    $meta = [];
    $sock = lg_connect($res['ip'], $port, $tls && !filter_var($host, FILTER_VALIDATE_IP) ? $host : null, $tls, 8.0, $meta);
    if ($sock === null) {
        return lg_err('No se pudo conectar a ' . $res['ip'] . ':' . $port . ' — ' . ($meta['error'] ?? 'sin respuesta'));
    }

    $req = "HEAD / HTTP/1.1\r\n"
         . "Host: {$host}\r\n"
         . "User-Agent: Centinela-LookingGlass/1.0 (+diagnostico)\r\n"
         . "Accept: */*\r\n"
         . "Connection: close\r\n\r\n";
    fwrite($sock, $req);

    $raw = '';
    $deadline = microtime(true) + 8;
    while (!feof($sock) && strlen($raw) < 32768 && microtime(true) < $deadline) {
        $chunk = fread($sock, 4096);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $raw .= $chunk;
    }
    fclose($sock);

    if (trim($raw) === '') {
        return lg_err('El servidor no devolvio ninguna cabecera.');
    }

    $lines  = preg_split('/\r?\n/', trim($raw));
    $status = array_shift($lines) ?: '';
    $h = [];
    foreach ($lines as $line) {
        if (str_contains($line, ':')) {
            [$k, $v] = explode(':', $line, 2);
            $h[strtolower(trim($k))] = trim($v);
        }
    }

    // Cabeceras de seguridad valoradas
    $checks = [
        'strict-transport-security' => ['HSTS', 'Obliga a usar HTTPS en visitas posteriores'],
        'content-security-policy'   => ['CSP', 'Limita de donde puede cargar recursos la pagina'],
        'x-content-type-options'    => ['X-Content-Type-Options', 'Evita que el navegador adivine el tipo de contenido'],
        'x-frame-options'           => ['X-Frame-Options', 'Impide que la pagina se embeba en un marco'],
        'referrer-policy'           => ['Referrer-Policy', 'Controla que informacion se filtra al navegar'],
        'permissions-policy'        => ['Permissions-Policy', 'Restringe camara, microfono y ubicacion'],
    ];

    $rows = [];
    $score = 0;
    foreach ($checks as $key => [$label, $desc]) {
        $present = isset($h[$key]);
        if ($present) {
            $score++;
        }
        // X-Frame-Options es prescindible si la CSP ya declara frame-ancestors
        $mitigated = !$present && $key === 'x-frame-options'
            && isset($h['content-security-policy'])
            && str_contains($h['content-security-policy'], 'frame-ancestors');
        if ($mitigated) {
            $score++;
        }
        $rows[] = lg_row(
            $label,
            $present ? mb_strimwidth($h[$key], 0, 70, '…') : ($mitigated ? 'cubierta por la CSP' : 'ausente'),
            $present || $mitigated ? 'good' : 'warn',
            $present || $mitigated ? '' : $desc
        );
    }

    $total = count($checks);
    $grade = match (true) {
        $score >= $total      => ['A', 'good'],
        $score >= $total - 1  => ['B', 'good'],
        $score >= $total - 2  => ['C', 'warn'],
        $score >= $total - 3  => ['D', 'warn'],
        default               => ['F', 'crit'],
    };

    // Cabeceras que revelan mas de lo necesario
    $leaks = [];
    foreach (['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'] as $k) {
        if (isset($h[$k])) {
            $leaks[] = $k . ': ' . $h[$k];
        }
    }

    $blocks = [
        lg_block('score', 'Nota de cabeceras de seguridad', [
            'grade' => $grade[0],
            'score' => $score,
            'total' => $total,
            'label' => "{$score} de {$total} cabeceras recomendadas",
        ], $grade[1]),
        lg_block('rows', 'Cabeceras de seguridad', $rows),
    ];

    if ($leaks) {
        $blocks[] = lg_block('rows', 'Informacion revelada', array_map(
            fn($l) => lg_row(explode(':', $l)[0], trim(explode(':', $l, 2)[1]), 'warn',
                'revela detalles de la tecnologia del servidor'),
            $leaks
        ), 'warn');
    }

    $allRows = [lg_row('Respuesta', $status)];
    foreach ($h as $k => $v) {
        $allRows[] = lg_row($k, mb_strimwidth($v, 0, 90, '…'));
    }
    $blocks[] = lg_block('rows', 'Todas las cabeceras (' . count($h) . ')', $allRows);

    $out = $status . "\n" . str_repeat('-', 50) . "\n";
    foreach ($h as $k => $v) {
        $out .= sprintf("%-32s %s\n", $k . ':', $v);
    }

    return lg_ok(trim($out), $blocks, ['target' => $res['ip']]);
}

// ---------------------------------------------------------------------------
// Listas negras (DNSBL)
// ---------------------------------------------------------------------------
//
// Consultar una DNSBL no es tan simple como "si responde, esta listada".
// Dos trampas reales:
//
//   1. Los codigos de la familia 127.255.255.x NO son listados: son avisos de
//      la propia lista. Spamhaus devuelve 127.255.255.254 cuando la consulta
//      llega desde un resolver publico, lo que daria un positivo en TODAS las
//      direcciones, incluidas las de Google.
//   2. Muchas listas solo responden a determinados origenes, y otras han
//      cerrado. Dar "limpia" por una lista que no contesta es tan enganoso
//      como dar un falso positivo.
//
// Por eso cada lista se sondea antes con las entradas de prueba universales
// (127.0.0.2 siempre listada, 127.0.0.1 nunca) y solo se informa de aquellas
// que demuestran responder correctamente desde este servidor.

/** Entradas de prueba que toda DNSBL bien mantenida implementa. */
const DNSBL_PROBE_LISTED = '2.0.0.127';
const DNSBL_PROBE_CLEAN  = '1.0.0.127';

/** Listas consultadas, con su nombre visible. */
function dnsbl_lists(): array
{
    return [
        'zen.spamhaus.org'        => 'Spamhaus ZEN',
        'bl.spamcop.net'          => 'SpamCop',
        'b.barracudacentral.org'  => 'Barracuda',
        'psbl.surriel.com'        => 'PSBL',
        'dnsbl-1.uceprotect.net'  => 'UCEPROTECT nivel 1',
        'all.s5h.net'             => 's5h',
        'spam.dnsbl.anonmails.de' => 'Anonmails',
        'truncate.gbudb.net'      => 'GBUdb Truncate',
        'dnsbl.dronebl.org'       => 'DroneBL',
        'bl.blocklist.de'         => 'Blocklist.de',
    ];
}

/** Consulta una DNSBL con un resolver concreto. Devuelve los codigos A. */
function dnsbl_query(string $name, ?string $resolver): array
{
    $dig = bin_path('dig');
    if ($dig === null) {
        $recs = @dns_get_record($name, DNS_A) ?: [];
        return array_values(array_filter(array_column($recs, 'ip')));
    }

    $cmd = [$dig, '+short', '+time=2', '+tries=1'];
    if ($resolver !== null) {
        $cmd[] = '@' . $resolver;
    }
    $cmd[] = $name;
    $cmd[] = 'A';

    $out = lg_proc($cmd, 6);
    $codes = [];
    foreach (explode("\n", $out) as $line) {
        $line = trim($line);
        if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $codes[] = $line;
        }
    }
    return $codes;
}

/**
 * Interpreta los codigos devueltos por una DNSBL.
 * @return string 'listed' | 'clean' | 'error'
 */
function dnsbl_classify(array $codes): string
{
    if (!$codes) {
        return 'clean';
    }
    foreach ($codes as $c) {
        // 127.255.255.x = mensaje de la lista, nunca un listado
        if (str_starts_with($c, '127.255.255.')) {
            return 'error';
        }
    }
    foreach ($codes as $c) {
        if (str_starts_with($c, '127.') && $c !== '127.0.0.0' && $c !== '127.0.0.1') {
            return 'listed';
        }
    }
    // Respuesta fuera del rango convenido: no es interpretable
    return 'error';
}

/** Cache compartida de sondeos, escribible por el usuario web. */
function dnsbl_cache_file(): string
{
    global $CFG;
    $dir = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/webcache';
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }
    return $dir . '/dnsbl_probe.json';
}

/**
 * Decide, para cada lista, que resolver da respuestas validas.
 * El resultado se cachea seis horas: es una propiedad del servidor, no de
 * la consulta, y sondear en cada peticion seria un desperdicio.
 *
 * @return array zona => ['resolver'=>string|null|false, 'reason'=>string]
 *               resolver === false significa que la lista no es consultable.
 */
function dnsbl_probe(): array
{
    $file = dnsbl_cache_file();
    if (is_readable($file)) {
        $d = json_decode((string) @file_get_contents($file), true);
        if (is_array($d) && (time() - (int) ($d['at'] ?? 0)) < 21600 && !empty($d['map'])) {
            return $d['map'];
        }
    }

    // Candidatos: primero un resolver local (las listas suelen rechazar los
    // publicos), despues el del sistema.
    $candidates = [];
    if (dnsbl_query('one.one.one.one', '127.0.0.1')) {
        $candidates[] = '127.0.0.1';
    }
    $candidates[] = null;

    $map = [];
    foreach (array_keys(dnsbl_lists()) as $zone) {
        $map[$zone] = ['resolver' => false, 'reason' => 'la lista no respondio'];
        foreach ($candidates as $r) {
            $listed = dnsbl_query(DNSBL_PROBE_LISTED . '.' . $zone, $r);
            if (dnsbl_classify($listed) !== 'listed') {
                if (dnsbl_classify($listed) === 'error') {
                    $map[$zone]['reason'] = 'la lista rechaza las consultas desde este servidor';
                }
                continue;
            }
            // La entrada limpia no debe aparecer listada
            if (dnsbl_classify(dnsbl_query(DNSBL_PROBE_CLEAN . '.' . $zone, $r)) === 'listed') {
                $map[$zone]['reason'] = 'la lista devuelve resultados incoherentes';
                continue;
            }
            $map[$zone] = ['resolver' => $r, 'reason' => ''];
            break;
        }
    }

    @file_put_contents($file, json_encode(['at' => time(), 'map' => $map]), LOCK_EX);
    return $map;
}

function lg_rbl(string $target, array $options): array
{
    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip = $res['ip'];
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return lg_err('La comprobacion de listas negras solo admite IPv4.');
    }

    $rev   = implode('.', array_reverse(explode('.', $ip)));
    $probe = dnsbl_probe();
    $lists = dnsbl_lists();

    $rows = [];
    $skipped = [];
    $listed = 0;
    $checked = 0;

    foreach ($lists as $zone => $label) {
        $cfg = $probe[$zone] ?? ['resolver' => false, 'reason' => 'sin sondear'];

        if ($cfg['resolver'] === false) {
            $skipped[] = lg_row($label, 'no consultable', '', $cfg['reason']);
            continue;
        }

        $checked++;
        $codes = dnsbl_query($rev . '.' . $zone, $cfg['resolver']);
        $verdict = dnsbl_classify($codes);

        if ($verdict === 'error') {
            $skipped[] = lg_row($label, 'sin respuesta valida', '', 'codigo ' . implode(', ', $codes));
            $checked--;
            continue;
        }

        if ($verdict === 'listed') {
            $listed++;
            $reason = 'codigo ' . implode(', ', $codes);
            $txt = dnsbl_query_txt($rev . '.' . $zone, $cfg['resolver']);
            if ($txt !== '') {
                $reason = mb_strimwidth($txt, 0, 90, '…');
            }
            $rows[] = lg_row($label, 'LISTADA', 'crit', $reason);
        } else {
            $rows[] = lg_row($label, 'limpia', 'good');
        }
    }

    if ($checked === 0) {
        return lg_ok(
            "No se pudo consultar ninguna lista para {$ip}.",
            [lg_block('rows', 'Sin resultado', array_merge(
                [lg_row('Direccion', $ip)],
                $skipped
            ), 'warn')],
            ['target' => $ip]
        );
    }

    $status = $listed === 0 ? 'good' : ($listed <= 2 ? 'warn' : 'crit');
    $blocks = [
        lg_block('score', 'Reputacion de la direccion', [
            'grade' => $listed === 0 ? 'LIMPIA' : (string) $listed,
            'score' => $checked - $listed,
            'total' => $checked,
            'label' => $listed === 0
                ? "No aparece en ninguna de las {$checked} listas consultadas"
                : "Aparece en {$listed} de {$checked} listas consultadas",
        ], $status),
        lg_block('rows', 'Listas consultadas (' . $checked . ')', $rows, $status),
    ];

    if ($skipped) {
        $blocks[] = lg_block('rows', 'No consultadas (' . count($skipped) . ')', $skipped);
    }

    $out = "Reputacion de {$ip}\n" . str_repeat('-', 52) . "\n";
    foreach ($rows as $r) {
        $out .= sprintf("%-24s %-12s %s\n", $r['k'], $r['v'], $r['note'] ?: '');
    }
    if ($skipped) {
        $out .= "\nNo consultadas:\n";
        foreach ($skipped as $r) {
            $out .= sprintf("%-24s %s\n", $r['k'], $r['note'] ?: $r['v']);
        }
    }

    return lg_ok(trim($out), $blocks, ['target' => $ip]);
}

/** Motivo publicado por la lista, si lo hay. */
function dnsbl_query_txt(string $name, ?string $resolver): string
{
    $dig = bin_path('dig');
    if ($dig === null) {
        $recs = @dns_get_record($name, DNS_TXT) ?: [];
        return trim((string) ($recs[0]['txt'] ?? ''));
    }
    $cmd = [$dig, '+short', '+time=2', '+tries=1'];
    if ($resolver !== null) {
        $cmd[] = '@' . $resolver;
    }
    $cmd[] = $name;
    $cmd[] = 'TXT';
    return trim(trim(explode("\n", lg_proc($cmd, 6))[0], '"'));
}

// ---------------------------------------------------------------------------
// RDAP (el sustituto moderno de WHOIS)
// ---------------------------------------------------------------------------

function lg_rdap(string $target, array $options): array
{
    $isIp = (bool) filter_var($target, FILTER_VALIDATE_IP);

    if ($isIp && lg_is_private_ip($target)) {
        return lg_err('Las direcciones privadas o reservadas no estan permitidas.');
    }
    if (!$isIp) {
        // Para dominios comprobamos que existan antes de consultar
        $r = lg_resolve($target);
        if (!$r['ok'] && !str_contains($r['error'], 'no resuelve')) {
            return lg_err($r['error']);
        }
    }

    $path = $isIp ? 'ip/' : 'domain/';
    $json = lg_fetch_json('https://rdap.org/' . $path . rawurlencode($target));
    if ($json === null) {
        return lg_err('El servicio RDAP no respondio. Intentalo de nuevo en unos segundos.');
    }
    if (isset($json['errorCode'])) {
        return lg_err('RDAP: ' . ($json['title'] ?? ('codigo ' . $json['errorCode'])));
    }

    // Contactos: buscamos abuso y titular
    $abuse = $registrant = $registrar = null;
    $walk = function ($entities) use (&$walk, &$abuse, &$registrant, &$registrar) {
        foreach ($entities ?? [] as $e) {
            $roles = $e['roles'] ?? [];
            $name  = null;
            $email = null;
            foreach (($e['vcardArray'][1] ?? []) as $f) {
                if (($f[0] ?? '') === 'fn')    { $name  = $f[3] ?? null; }
                if (($f[0] ?? '') === 'email') { $email = $f[3] ?? null; }
            }
            if (in_array('abuse', $roles, true) && $email) { $abuse = $email; }
            if (in_array('registrant', $roles, true) && $name) { $registrant = $name; }
            if (in_array('registrar', $roles, true) && $name) { $registrar = $name; }
            if (!empty($e['entities'])) { $walk($e['entities']); }
        }
    };
    $walk($json['entities'] ?? []);

    $events = [];
    foreach ($json['events'] ?? [] as $e) {
        $label = [
            'registration' => 'Registrado',
            'expiration'   => 'Caduca',
            'last changed' => 'Ultimo cambio',
            'last update of RDAP database' => 'Actualizacion RDAP',
            'transfer'     => 'Transferido',
        ][$e['eventAction'] ?? ''] ?? ($e['eventAction'] ?? '');
        if ($label !== '' && !empty($e['eventDate'])) {
            $ts = strtotime($e['eventDate']);
            $events[$label] = $ts ? date('d/m/Y', $ts) : $e['eventDate'];
        }
    }

    $rows = [];
    if ($isIp) {
        $rows[] = lg_row('Rango', ($json['startAddress'] ?? '?') . ' — ' . ($json['endAddress'] ?? '?'));
        $rows[] = lg_row('Red', $json['name'] ?? '—');
        $rows[] = lg_row('Tipo', $json['type'] ?? '—');
        $rows[] = lg_row('Pais', $json['country'] ?? '—');
        $rows[] = lg_row('Identificador', $json['handle'] ?? '—');
    } else {
        $rows[] = lg_row('Dominio', strtoupper((string) ($json['ldhName'] ?? $target)));
        if ($registrar)  { $rows[] = lg_row('Registrador', $registrar); }
        if ($registrant) { $rows[] = lg_row('Titular', $registrant); }
        $st = $json['status'] ?? [];
        if ($st) {
            $rows[] = lg_row('Estado', implode(', ', array_slice($st, 0, 4)));
        }
        // Caducidad proxima
        foreach ($json['events'] ?? [] as $e) {
            if (($e['eventAction'] ?? '') === 'expiration' && !empty($e['eventDate'])) {
                $ts = strtotime($e['eventDate']);
                if ($ts) {
                    $d = (int) floor(($ts - time()) / 86400);
                    $rows[] = lg_row('Caduca en', $d . ' dias',
                        $d < 0 ? 'crit' : ($d < 30 ? 'warn' : 'good'),
                        date('d/m/Y', $ts));
                }
            }
        }
    }
    if ($abuse) {
        $rows[] = lg_row('Contacto de abuso', $abuse, 'good', 'para denunciar actividad maliciosa');
    }

    $blocks = [lg_block('rows', $isIp ? 'Asignacion de red' : 'Registro del dominio', $rows)];

    if ($events) {
        $blocks[] = lg_block('rows', 'Fechas', array_map(
            fn($k, $v) => lg_row($k, $v), array_keys($events), array_values($events)
        ));
    }

    if (!empty($json['nameservers'])) {
        $ns = array_values(array_filter(array_map(fn($n) => $n['ldhName'] ?? null, $json['nameservers'])));
        if ($ns) {
            $blocks[] = lg_block('tags', 'Servidores de nombres', $ns);
        }
    }

    $remarks = [];
    foreach ($json['remarks'] ?? [] as $r) {
        foreach ($r['description'] ?? [] as $d) {
            $remarks[] = $d;
        }
    }

    $out = ($isIp ? "RDAP de la direccion {$target}" : "RDAP del dominio {$target}") . "\n" . str_repeat('-', 50) . "\n";
    foreach ($rows as $r) {
        $out .= sprintf("%-22s %s\n", $r['k'] . ':', is_array($r['v']) ? implode(', ', $r['v']) : $r['v']);
    }
    foreach ($events as $k => $v) {
        $out .= sprintf("%-22s %s\n", $k . ':', $v);
    }

    return lg_ok(trim($out), $blocks, ['target' => $target]);
}

/** Descarga JSON de una URL de confianza fijada en el codigo. */
function lg_fetch_json(string $url, int $timeout = 12, int $maxBytes = 1048576): ?array
{
    $ctx = stream_context_create([
        'http' => [
            'method'        => 'GET',
            'timeout'       => $timeout,
            'header'        => "Accept: application/rdap+json, application/json\r\n"
                             . "User-Agent: Centinela-LookingGlass/1.0\r\n",
            'follow_location' => 1,
            'max_redirects' => 4,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
    ]);
    $body = @file_get_contents($url, false, $ctx, 0, $maxBytes);
    if ($body === false) {
        return null;
    }
    $d = json_decode($body, true);
    return is_array($d) ? $d : null;
}

// ---------------------------------------------------------------------------
// DNS inverso con validacion directa-inversa
// ---------------------------------------------------------------------------

function lg_rdns(string $target, array $options): array
{
    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip = $res['ip'];

    $dig = bin_path('dig');
    $ptr = '';
    if ($dig !== null) {
        $ptr = trim(explode("\n", lg_proc([$dig, '+short', '+time=3', '+tries=2', '-x', $ip], 10))[0]);
        $ptr = rtrim($ptr, '.');
    }
    if ($ptr === '' || $ptr === 'Sin salida.') {
        $blocks = [lg_block('rows', 'DNS inverso', [
            lg_row('Direccion', $ip),
            lg_row('Registro PTR', 'ninguno', 'crit', 'los servidores de correo suelen rechazar el correo de IPs sin PTR'),
        ], 'crit')];
        return lg_ok("La direccion {$ip} no tiene registro PTR.", $blocks, ['target' => $ip]);
    }

    // Comprobacion directa-inversa: el nombre debe volver a la misma IP
    $fwd = [];
    foreach (@dns_get_record($ptr, DNS_A + DNS_AAAA) ?: [] as $r) {
        if (!empty($r['ip']))   { $fwd[] = $r['ip']; }
        if (!empty($r['ipv6'])) { $fwd[] = $r['ipv6']; }
    }
    $match = in_array($ip, $fwd, true);

    $rows = [
        lg_row('Direccion', $ip),
        lg_row('Registro PTR', $ptr, 'good'),
        lg_row('El nombre resuelve a', $fwd ? implode(', ', $fwd) : 'nada',
            $match ? 'good' : 'crit',
            $match ? '' : 'no coincide con la direccion de origen'),
        lg_row('Validacion directa-inversa', $match ? 'correcta' : 'fallida',
            $match ? 'good' : 'crit',
            $match ? 'la configuracion es coherente'
                   : 'Gmail, Outlook y otros rechazan correo en esta situacion'),
    ];

    $out = "DNS inverso de {$ip}\n" . str_repeat('-', 50) . "\n"
        . "PTR            : {$ptr}\n"
        . "Directo        : " . ($fwd ? implode(', ', $fwd) : 'sin resultado') . "\n"
        . "Coincidencia   : " . ($match ? 'correcta' : 'FALLIDA');

    return lg_ok($out, [lg_block('rows', 'DNS inverso', $rows, $match ? 'good' : 'crit')], ['target' => $ip]);
}

// ---------------------------------------------------------------------------
// Diagnostico de correo de un dominio
// ---------------------------------------------------------------------------

function lg_mail(string $target, array $options): array
{
    $domain = rtrim(strtolower($target), '.');
    if (filter_var($domain, FILTER_VALIDATE_IP)) {
        return lg_err('Indica un dominio, no una direccion IP.');
    }

    // Servidores de correo
    $mx = [];
    foreach (@dns_get_record($domain, DNS_MX) ?: [] as $r) {
        $mx[] = ['host' => rtrim((string) $r['target'], '.'), 'pri' => (int) ($r['pri'] ?? 0)];
    }
    usort($mx, fn($a, $b) => $a['pri'] <=> $b['pri']);

    // SPF
    $spf = null;
    foreach (@dns_get_record($domain, DNS_TXT) ?: [] as $r) {
        $t = (string) ($r['txt'] ?? '');
        if (stripos($t, 'v=spf1') === 0) {
            $spf = $t;
        }
    }

    // DMARC
    $dmarc = null;
    foreach (@dns_get_record('_dmarc.' . $domain, DNS_TXT) ?: [] as $r) {
        $t = (string) ($r['txt'] ?? '');
        if (stripos($t, 'v=DMARC1') === 0) {
            $dmarc = $t;
        }
    }

    // DKIM: probamos los selectores mas habituales
    $dkim = [];
    foreach (['default', 'mail', 'google', 'selector1', 'selector2', 'k1', 'dkim', 's1'] as $sel) {
        foreach (@dns_get_record($sel . '._domainkey.' . $domain, DNS_TXT) ?: [] as $r) {
            $t = (string) ($r['txt'] ?? '');
            if (stripos($t, 'v=DKIM1') !== false || stripos($t, 'p=') !== false) {
                $dkim[] = $sel;
                break;
            }
        }
    }

    $policy = null;
    if ($dmarc !== null && preg_match('/\bp=(\w+)/i', $dmarc, $m)) {
        $policy = strtolower($m[1]);
    }

    $rows = [
        lg_row('Servidores MX', $mx ? count($mx) . ' configurado(s)' : 'ninguno',
            $mx ? 'good' : 'crit', $mx ? '' : 'el dominio no puede recibir correo'),
        lg_row('SPF', $spf ? mb_strimwidth($spf, 0, 70, '…') : 'ausente',
            $spf ? 'good' : 'warn',
            $spf ? (str_contains($spf, '-all') ? 'politica estricta' : (str_contains($spf, '~all') ? 'politica moderada' : 'termina en +all o ?all, muy permisivo')) : 'sin SPF cualquiera puede suplantar el dominio'),
        lg_row('DKIM', $dkim ? 'selectores: ' . implode(', ', $dkim) : 'no encontrado',
            $dkim ? 'good' : 'warn',
            $dkim ? '' : 'no se hallaron los selectores habituales; puede existir con otro nombre'),
        lg_row('DMARC', $dmarc ? mb_strimwidth($dmarc, 0, 70, '…') : 'ausente',
            $dmarc ? ($policy === 'none' ? 'warn' : 'good') : 'warn',
            $dmarc === null ? 'sin DMARC no hay politica frente a la suplantacion'
                : ($policy === 'none' ? 'en modo observacion: no bloquea nada' : "politica: {$policy}")),
    ];

    $score = 0;
    foreach ([$mx, $spf, $dkim, $dmarc] as $x) {
        if ($x) { $score++; }
    }
    $status = $score >= 4 ? 'good' : ($score >= 2 ? 'warn' : 'crit');

    $blocks = [
        lg_block('score', 'Proteccion del correo', [
            'grade' => ['F', 'D', 'C', 'B', 'A'][$score] ?? 'F',
            'score' => $score,
            'total' => 4,
            'label' => "{$score} de 4 mecanismos configurados",
        ], $status),
        lg_block('rows', 'Autenticacion', $rows),
    ];

    if ($mx) {
        $mxRows = [];
        foreach (array_slice($mx, 0, 8) as $m) {
            $ips = [];
            foreach (@dns_get_record($m['host'], DNS_A) ?: [] as $a) {
                if (!empty($a['ip'])) { $ips[] = $a['ip']; }
            }
            $mxRows[] = lg_row('Prioridad ' . $m['pri'], $m['host'], '', $ips ? implode(', ', $ips) : 'no resuelve');
        }
        $blocks[] = lg_block('rows', 'Servidores de correo', $mxRows);
    }

    $out = "Diagnostico de correo de {$domain}\n" . str_repeat('-', 50) . "\n";
    foreach ($mx as $m) {
        $out .= sprintf("MX %-4d %s\n", $m['pri'], $m['host']);
    }
    $out .= "\nSPF   : " . ($spf ?: 'ausente') . "\n";
    $out .= 'DKIM  : ' . ($dkim ? implode(', ', $dkim) : 'no encontrado') . "\n";
    $out .= 'DMARC : ' . ($dmarc ?: 'ausente') . "\n";

    return lg_ok(trim($out), $blocks, ['target' => $domain]);
}

// ---------------------------------------------------------------------------
// Escaneo de puertos habituales, en paralelo
// ---------------------------------------------------------------------------

function lg_portscan(string $target, array $options): array
{
    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip = $res['ip'];

    $ports = [
        21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS',
        80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP', 443 => 'HTTPS', 445 => 'SMB',
        465 => 'SMTPS', 587 => 'Envio SMTP', 993 => 'IMAPS', 995 => 'POP3S',
        3306 => 'MySQL', 3389 => 'RDP', 5432 => 'PostgreSQL', 6379 => 'Redis',
        8080 => 'HTTP alt', 8443 => 'HTTPS alt', 27017 => 'MongoDB',
    ];

    // Conexiones no bloqueantes lanzadas a la vez: el escaneo completo
    // tarda lo que el puerto mas lento, no la suma de todos.
    $sockets = [];
    $host = str_contains($ip, ':') ? "[{$ip}]" : $ip;
    foreach (array_keys($ports) as $p) {
        $errno = 0;
        $errstr = '';
        $s = @stream_socket_client(
            "tcp://{$host}:{$p}", $errno, $errstr, 3,
            STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT
        );
        if ($s !== false) {
            $sockets[$p] = $s;
        }
    }

    $open = [];
    $deadline = microtime(true) + 4.0;
    while ($sockets && microtime(true) < $deadline) {
        $r = null;
        $w = array_values($sockets);
        $e = null;
        if (@stream_select($r, $w, $e, 0, 200000) === false) {
            break;
        }
        foreach ($w as $s) {
            $p = array_search($s, $sockets, true);
            if ($p === false) {
                continue;
            }
            // Si el socket es escribible, la conexion se completo
            $meta = stream_get_meta_data($s);
            if (empty($meta['timed_out'])) {
                $peer = @stream_socket_get_name($s, true);
                if ($peer !== false && $peer !== '') {
                    $open[] = (int) $p;
                }
            }
            fclose($s);
            unset($sockets[$p]);
        }
    }
    foreach ($sockets as $s) {
        fclose($s);
    }
    sort($open);

    // Puertos que conviene no tener abiertos a Internet
    $riesgo = [23 => 'protocolo sin cifrar', 445 => 'exposicion de SMB',
               3306 => 'base de datos expuesta', 3389 => 'escritorio remoto expuesto',
               5432 => 'base de datos expuesta', 6379 => 'Redis suele carecer de autenticacion',
               27017 => 'MongoDB expuesto'];

    $rows = [];
    $alertas = 0;
    foreach ($ports as $p => $name) {
        $isOpen = in_array($p, $open, true);
        if (!$isOpen) {
            continue;
        }
        $bad = isset($riesgo[$p]);
        if ($bad) {
            $alertas++;
        }
        $rows[] = lg_row($p . '/tcp', $name, $bad ? 'crit' : 'good', $bad ? $riesgo[$p] : 'abierto');
    }

    $status = $alertas > 0 ? 'crit' : 'good';
    $blocks = [
        lg_block('score', 'Puertos accesibles', [
            'grade' => (string) count($open),
            'score' => count($open),
            'total' => count($ports),
            'label' => count($open) . ' abiertos de ' . count($ports) . ' comprobados'
                . ($alertas ? " · {$alertas} merecen atencion" : ''),
        ], $status),
    ];
    $blocks[] = $rows
        ? lg_block('rows', 'Servicios detectados', $rows, $status)
        : lg_block('rows', 'Servicios detectados', [lg_row('Resultado', 'ningun puerto abierto entre los comprobados', 'good')]);

    $out = "Escaneo de {$ip}\n" . str_repeat('-', 50) . "\n";
    foreach ($ports as $p => $name) {
        $out .= sprintf("%6d/tcp  %-14s %s\n", $p, $name, in_array($p, $open, true) ? 'ABIERTO' : 'cerrado o filtrado');
    }

    return lg_ok(trim($out), $blocks, ['target' => $ip]);
}


// ---------------------------------------------------------------------------
// Mapa BGP: donde anuncia sus rutas un sistema autonomo
// ---------------------------------------------------------------------------

/**
 * Los datos salen de RIPEstat (RIPE NCC), que agrega la tabla BGP vista por
 * los colectores RIS y la geolocalizacion MaxMind GeoLite de cada prefijo.
 * Tres consultas por ASN, cacheadas media hora: el mapa de anuncios de un AS
 * no cambia por minutos, y RIPEstat es un servicio publico que no conviene
 * castigar desde una pagina abierta a internet.
 */
function lg_asnmap_cache(string $key): string
{
    global $CFG;
    $dir = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/webcache';
    return is_dir($dir) && is_writable($dir) ? $dir . '/asnmap_' . $key . '.json' : '';
}

/** ASN de una IP via Team Cymru. Devuelve numero o cadena vacia. */
function lg_origin_asn(string $ip): string
{
    $dig = bin_path('dig');
    if ($dig === null) {
        return '';
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $q = implode('.', array_reverse(explode('.', $ip))) . '.origin.asn.cymru.com';
    } else {
        $hex = bin2hex((string) inet_pton($ip));
        $q = implode('.', array_reverse(str_split($hex))) . '.origin6.asn.cymru.com';
    }
    $txt = trim(lg_proc([$dig, '+short', '+time=3', '+tries=2', $q, 'TXT'], 10));
    $first = trim(explode("\n", $txt)[0], '" \t');
    $asn = trim(explode(' ', explode('|', $first)[0] ?? '')[0]);
    return ctype_digit($asn) ? $asn : '';
}

function lg_asnmap(string $target, array $options): array
{
    // ------------------------------------------------ resolver el ASN -----
    if (preg_match('/^(?:as)?(\d{1,10})$/i', trim($target), $m)) {
        $asn = $m[1];
    } else {
        $res = lg_resolve($target);
        if (!$res['ok']) {
            return lg_err($res['error']);
        }
        $asn = lg_origin_asn($res['ip']);
        if ($asn === '') {
            return lg_err('No se pudo determinar el sistema autonomo de ' . $res['ip'] . '.');
        }
    }

    // ------------------------------------------------------- cache --------
    $cf = lg_asnmap_cache($asn);
    if ($cf !== '' && is_file($cf) && (time() - (int) @filemtime($cf)) < 1800) {
        $prev = json_decode((string) @file_get_contents($cf), true);
        if (is_array($prev) && isset($prev['blocks'])) {
            $prev['meta']['cache'] = 'hit';
            return $prev;
        }
    }

    // ------------------------------------------- consultas a RIPEstat -----
    $base = 'https://stat.ripe.net/data/';
    $suf  = '/data.json?soft_limit=ignore&resource=AS' . $asn;

    $geo = lg_fetch_json($base . 'maxmind-geo-lite-announced-by-as' . $suf, 20, 6291456);
    if (!is_array($geo) || ($geo['status'] ?? '') !== 'ok') {
        return lg_err('RIPEstat no ha devuelto datos para AS' . $asn . '. Puede ser un ASN sin anuncios o un fallo temporal del servicio.');
    }
    $rst = lg_fetch_json($base . 'routing-status' . $suf, 15);
    $nbr = lg_fetch_json($base . 'asn-neighbours' . $suf, 15);

    // Nombre del operador via Team Cymru
    $org = '';
    $dig = bin_path('dig');
    if ($dig !== null) {
        $atxt = trim(lg_proc([$dig, '+short', '+time=3', '+tries=2', "AS{$asn}.asn.cymru.com", 'TXT'], 10));
        $ap = explode('|', trim($atxt, '" \t'));
        $org = isset($ap[4]) ? trim($ap[4]) : '';
    }

    // -------------------------------------------------- agregacion --------
    $puntos = [];        // "lat,lon" => punto
    $paises = [];        // cc => n prefijos
    $v4 = $v6 = 0;
    $sinGeo = 0;

    foreach ((array) ($geo['data']['located_resources'] ?? []) as $r) {
        $pfx = (string) ($r['resource'] ?? '');
        if ($pfx === '') {
            continue;
        }
        $esV6 = str_contains($pfx, ':');
        $esV6 ? $v6++ : $v4++;

        $locs = (array) ($r['locations'] ?? []);
        if (!$locs) {
            $sinGeo++;
            continue;
        }
        foreach ($locs as $l) {
            $cc  = strtoupper((string) ($l['country'] ?? ''));
            $lat = (float) ($l['latitude'] ?? 0);
            $lon = (float) ($l['longitude'] ?? 0);
            if ($cc === '' || ($lat === 0.0 && $lon === 0.0)) {
                continue;
            }
            $k = round($lat, 1) . ',' . round($lon, 1);
            if (!isset($puntos[$k])) {
                $puntos[$k] = [
                    'lat' => round($lat, 2), 'lon' => round($lon, 2),
                    'city' => (string) ($l['city'] ?? ''), 'cc' => $cc,
                    'n' => 0, 'v6' => 0, 'pfx' => [],
                ];
            }
            $puntos[$k]['n']++;
            if ($esV6) {
                $puntos[$k]['v6']++;
            }
            if (count($puntos[$k]['pfx']) < 12) {
                $puntos[$k]['pfx'][] = $pfx;
            }
            $paises[$cc] = ($paises[$cc] ?? 0) + 1;
        }
    }

    // Los puntos mas gordos primero; tope para que la pagina no sufra
    usort($puntos, fn($a, $b) => $b['n'] <=> $a['n']);
    $recortados = max(0, count($puntos) - 400);
    $puntos = array_slice(array_values($puntos), 0, 400);
    arsort($paises);

    // ------------------------------------------------------ resumen -------
    $an  = $rst['data']['announced_space'] ?? [];
    $vis = $rst['data']['visibility'] ?? [];
    $nc  = $nbr['data']['neighbour_counts'] ?? [];

    $visTxt = '';
    if (!empty($vis['v4']['total_ris_peers'])) {
        $visTxt = $vis['v4']['ris_peers_seeing'] . ' de ' . $vis['v4']['total_ris_peers'] . ' colectores RIS';
    }

    $rows = [
        lg_row('Sistema autonomo', 'AS' . $asn),
        lg_row('Operador', $org ?: 'desconocido'),
        lg_row('Prefijos IPv4', number_format((int) ($an['v4']['prefixes'] ?? $v4), 0, ',', '.')
            . (!empty($an['v4']['ips']) ? ' (' . number_format((int) $an['v4']['ips'], 0, ',', '.') . ' direcciones)' : '')),
        lg_row('Prefijos IPv6', number_format((int) ($an['v6']['prefixes'] ?? $v6), 0, ',', '.')),
        lg_row('Visibilidad global', $visTxt ?: '—', $visTxt !== '' &&
            ($vis['v4']['ris_peers_seeing'] ?? 0) >= ($vis['v4']['total_ris_peers'] ?? 1) * 0.95 ? 'good' : ''),
        lg_row('Vecinos BGP', !empty($nc) ? (($nc['unique'] ?? 0) . ' (' . ($nc['left'] ?? 0) . ' transito, '
            . ($nc['right'] ?? 0) . ' clientes/pares)') : '—'),
        lg_row('Paises con presencia', (string) count($paises)),
    ];

    $vecinos = [];
    foreach ((array) ($nbr['data']['neighbours'] ?? []) as $n) {
        if (count($vecinos) >= 14) {
            break;
        }
        $vecinos[] = (($n['type'] ?? '') === 'left' ? '↑ ' : '↓ ') . 'AS' . $n['asn'];
    }

    // ------------------------------------------------- salida en texto ----
    $out = "Anuncios BGP de AS{$asn}" . ($org !== '' ? " ({$org})" : '') . "\n" . str_repeat('-', 56) . "\n";
    foreach ($rows as $r) {
        $out .= sprintf("%-22s %s\n", $r['k'] . ':', $r['v']);
    }
    $out .= "\nReparto por pais (prefijos localizados):\n";
    foreach (array_slice($paises, 0, 15, true) as $cc => $n) {
        $out .= sprintf("  %-4s %d\n", $cc, $n);
    }
    if ($sinGeo > 0) {
        $out .= "\n{$sinGeo} prefijo(s) sin geolocalizacion conocida.\n";
    }
    $out .= "\nFuentes: RIPEstat (RIPE NCC) y MaxMind GeoLite. La geolocalizacion de\n"
          . "prefijos es aproximada: situa el registro, no necesariamente el trafico.\n";

    $bloques = [
        lg_block('rows', 'Sistema autonomo', $rows),
        lg_block('map', 'Mapa de anuncios', [
            'asn'      => 'AS' . $asn,
            'org'      => $org,
            'points'   => $puntos,
            'countries' => array_map(fn($cc, $n) => ['cc' => $cc, 'n' => $n],
                                     array_keys($paises), array_values($paises)),
            'clipped'  => $recortados,
            'nogeo'    => $sinGeo,
        ]),
    ];
    if ($vecinos) {
        $bloques[] = lg_block('tags', 'Vecinos BGP (↑ transito, ↓ cliente o par)', $vecinos);
    }

    $resultado = lg_ok(trim($out), $bloques, ['target' => 'AS' . $asn]);

    if ($cf !== '') {
        @file_put_contents($cf, json_encode($resultado, JSON_UNESCAPED_SLASHES), LOCK_EX);
        @chmod($cf, 0660);
    }
    return $resultado;
}


// ---------------------------------------------------------------------------
// Reputacion e historial de una IP
// ---------------------------------------------------------------------------

/**
 * Junta lo que las fuentes publicas sin clave saben de una IP: si los
 * sensores globales la han visto atacar (SANS ISC, blocklist.de), si esta en
 * redes secuestradas (Spamhaus DROP), si es un mando de botnet conocido
 * (Feodo Tracker de abuse.ch), si es salida de Tor, como se ha anunciado su
 * prefijo a lo largo de los anos (RIPEstat) y a quien reportar el abuso.
 *
 * Ninguna fuente es local: esta pagina es publica y no expone nada del
 * servidor que la sirve.
 */

/** Descarga con cache en disco: para las listas que se publican enteras. */
function lg_feed(string $key, string $url, int $ttl, int $maxBytes = 2097152): ?string
{
    global $CFG;
    $dir = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/webcache';
    $cf  = is_dir($dir) && is_writable($dir) ? $dir . '/feed_' . $key . '.txt' : '';

    if ($cf !== '' && is_file($cf) && (time() - (int) @filemtime($cf)) < $ttl) {
        return (string) @file_get_contents($cf);
    }
    $ctx = stream_context_create([
        'http' => ['timeout' => 12, 'header' => "User-Agent: Centinela-LookingGlass/1.0\r\n",
                   'follow_location' => 1, 'max_redirects' => 3],
        'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
    ]);
    $body = @file_get_contents($url, false, $ctx, 0, $maxBytes);
    if ($body === false) {
        // Si la descarga falla, una copia caducada sigue valiendo mas que nada
        return $cf !== '' && is_file($cf) ? (string) @file_get_contents($cf) : null;
    }
    if ($cf !== '') {
        @file_put_contents($cf, $body, LOCK_EX);
        @chmod($cf, 0660);
    }
    return $body;
}

function lg_reputation(string $target, array $options): array
{
    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip = $res['ip'];
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return lg_err('Es una direccion privada o reservada: no tiene reputacion publica.');
    }
    $esV4 = (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);

    $hallazgos = [];   // cada uno: [gravedad 0-2, texto]

    // ---- SANS ISC / DShield: sensores de ataque en todo el mundo ---------
    $isc = lg_fetch_json('https://isc.sans.edu/api/ip/' . rawurlencode($ip) . '?json', 12);
    $d   = is_array($isc) ? ($isc['ip'] ?? []) : [];
    $iscReports = (int) ($d['count'] ?? 0);
    $iscTargets = (int) ($d['attacks'] ?? 0);
    $rowsAtq = [
        lg_row('Informes de ataque', $iscReports > 0 ? number_format($iscReports, 0, ',', '.') : 'ninguno',
            $iscReports > 500 ? 'crit' : ($iscReports > 0 ? 'warn' : 'good'),
            'paquetes hostiles vistos por los sensores DShield'),
        lg_row('Objetivos distintos', $iscTargets > 0 ? number_format($iscTargets, 0, ',', '.') : '—'),
    ];
    if (!empty($d['mindate'])) {
        $rowsAtq[] = lg_row('Activa desde', (string) $d['mindate']);
    }
    if (!empty($d['maxdate'])) {
        $rowsAtq[] = lg_row('Visto por ultima vez', (string) $d['maxdate']);
    }
    if (!empty($d['threatfeeds'])) {
        // threatfeeds puede ser un objeto {feed: {...}}: nos quedamos con los nombres
        $tf = is_array($d['threatfeeds']) ? implode(', ', array_keys($d['threatfeeds'])) : (string) $d['threatfeeds'];
        $rowsAtq[] = lg_row('Listas de amenazas ISC', $tf, 'warn');
    }
    if ($iscReports > 0) {
        $hallazgos[] = [1, "los sensores de SANS ISC la han visto atacar ({$iscReports} informes)"];
    }

    // ---- blocklist.de: honeypots europeos, informes de fail2ban ----------
    $bld = lg_feed('bld_' . md5($ip), 'https://api.blocklist.de/api.php?ip=' . rawurlencode($ip), 900, 4096);
    if ($bld !== null && preg_match('/attacks:\s*(\d+).*?reports:\s*(\d+)/s', $bld, $m)) {
        $rowsAtq[] = lg_row('Ataques (blocklist.de)', $m[1] . ' ataques, ' . $m[2] . ' informes',
            (int) $m[1] > 0 ? 'warn' : 'good', 'red europea de honeypots y fail2ban');
        if ((int) $m[1] > 0) {
            $hallazgos[] = [1, "blocklist.de acumula {$m[1]} ataques reportados"];
        }
    }

    // ---- listas de amenazas --------------------------------------------
    $rowsAmz = [];

    // Spamhaus DROP: rangos secuestrados o alquilados a delincuentes
    if ($esV4) {
        $drop = lg_feed('spamhaus_drop', 'https://www.spamhaus.org/drop/drop_v4.json', 86400);
        $enDrop = '';
        foreach (explode("\n", (string) $drop) as $linea) {
            $e = json_decode(trim($linea), true);
            if (is_array($e) && !empty($e['cidr']) && ip_in_cidr($ip, (string) $e['cidr'])) {
                $enDrop = $e['cidr'] . ' (' . ($e['sblid'] ?? '') . ')';
                break;
            }
        }
        $rowsAmz[] = lg_row('Spamhaus DROP', $enDrop !== '' ? 'EN LA LISTA: ' . $enDrop : 'no listada',
            $enDrop !== '' ? 'crit' : 'good',
            $enDrop !== '' ? 'rango controlado por delincuentes: no deberia cursarse trafico' : 'redes secuestradas o criminales');
        if ($enDrop !== '') {
            $hallazgos[] = [2, 'pertenece a un rango de la lista DROP de Spamhaus'];
        }
    }

    // Feodo Tracker: mandos de botnet (Emotet, Dridex, QakBot...)
    $feodo = lg_feed('feodo_c2', 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', 21600);
    $c2 = null;
    foreach ((array) json_decode((string) $feodo, true) as $e) {
        if (($e['ip_address'] ?? '') === $ip) {
            $c2 = $e;
            break;
        }
    }
    $rowsAmz[] = lg_row('Botnet C2 (Feodo)', $c2 !== null
            ? strtoupper((string) ($c2['malware'] ?? '?')) . ' — estado ' . ($c2['status'] ?? '?')
            : 'no listada',
        $c2 !== null ? 'crit' : 'good', 'centros de mando de botnets conocidos, por abuse.ch');
    if ($c2 !== null) {
        $hallazgos[] = [2, 'figura como mando de la botnet ' . strtoupper((string) ($c2['malware'] ?? ''))];
    }

    // Salidas de Tor: anonimato, no malicia en si misma
    $tor = lg_feed('tor_exits', 'https://check.torproject.org/torbulkexitlist', 21600);
    $esTor = $tor !== null && preg_match('/^' . preg_quote($ip, '/') . '$/m', $tor) === 1;
    $rowsAmz[] = lg_row('Salida de Tor', $esTor ? 'si' : 'no', $esTor ? 'warn' : 'good',
        $esTor ? 'trafico anonimo: no es malicioso en si, pero impide atribuir' : '');
    if ($esTor) {
        $hallazgos[] = [1, 'es un nodo de salida de Tor'];
    }

    // ---- historial de enrutado ------------------------------------------
    $rh = lg_fetch_json('https://stat.ripe.net/data/routing-history/data.json?min_peers=10&resource='
        . rawurlencode($ip), 15, 4194304);
    $rowsRuta = [];
    $lineas = [];
    foreach ((array) ($rh['data']['by_origin'] ?? []) as $o) {
        foreach ((array) ($o['prefixes'] ?? []) as $pfx) {
            $mask = (int) (explode('/', (string) ($pfx['prefix'] ?? '/0'))[1] ?? 0);
            if ($mask < 8) {
                continue;   // artefactos tipo 0.0.0.0/1 de colectores antiguos
            }
            foreach ((array) ($pfx['timelines'] ?? []) as $t) {
                $lineas[] = [
                    'asn'   => (string) $o['origin'],
                    'pfx'   => (string) $pfx['prefix'],
                    'desde' => substr((string) ($t['starttime'] ?? ''), 0, 10),
                    'hasta' => substr((string) ($t['endtime'] ?? ''), 0, 10),
                ];
            }
        }
    }
    usort($lineas, fn($a, $b) => strcmp($b['hasta'], $a['hasta']));
    $enUso = date('Y-m-d', time() - 45 * 86400);
    foreach (array_slice($lineas, 0, 8) as $l) {
        $vigente = $l['hasta'] >= $enUso;
        $rowsRuta[] = lg_row('AS' . $l['asn'], $l['pfx'],
            $vigente ? 'good' : '',
            $l['desde'] . ' → ' . ($vigente ? 'hoy' : $l['hasta']));
    }
    $origenes = count(array_unique(array_column($lineas, 'asn')));
    if ($origenes > 3) {
        $hallazgos[] = [1, "su prefijo ha cambiado de operador {$origenes} veces: historial inestable"];
    }

    // ---- contacto de abuso ----------------------------------------------
    $ab = lg_fetch_json('https://stat.ripe.net/data/abuse-contact-finder/data.json?resource='
        . rawurlencode($ip), 10);
    $contactos = (array) ($ab['data']['abuse_contacts'] ?? []);

    // ---- veredicto -------------------------------------------------------
    $peor = 0;
    foreach ($hallazgos as $h2) {
        $peor = max($peor, $h2[0]);
    }
    [$verTxt, $verSt] = match (true) {
        $peor >= 2      => ['MALA REPUTACION', 'crit'],
        $peor === 1     => ['Con antecedentes', 'warn'],
        default         => ['Limpia en todas las fuentes consultadas', 'good'],
    };

    $rowsVer = [lg_row('Veredicto', $verTxt, $verSt)];
    foreach (array_slice($hallazgos, 0, 5) as $h2) {
        $rowsVer[] = lg_row('·', $h2[1], $h2[0] >= 2 ? 'crit' : 'warn');
    }
    if ($contactos) {
        $rowsVer[] = lg_row('Reportar abuso a', implode(', ', array_slice($contactos, 0, 2)));
    }

    // ---- salida en texto -------------------------------------------------
    $out = "Reputacion de {$ip}\n" . str_repeat('-', 56) . "\n";
    $out .= "Veredicto: {$verTxt}\n";
    foreach ($hallazgos as $h2) {
        $out .= '  - ' . $h2[1] . "\n";
    }
    $out .= "\nInformes de ataque (SANS ISC): " . ($iscReports ?: 'ninguno') . "\n";
    if ($lineas) {
        $out .= "\nHistorial de enrutado:\n";
        foreach (array_slice($lineas, 0, 8) as $l) {
            $out .= sprintf("  AS%-8s %-22s %s -> %s\n", $l['asn'], $l['pfx'], $l['desde'], $l['hasta']);
        }
    }
    if ($contactos) {
        $out .= "\nAbuso: " . implode(', ', $contactos) . "\n";
    }
    $out .= "\nFuentes: SANS ISC, blocklist.de, Spamhaus DROP, abuse.ch Feodo Tracker,\n"
          . "Tor Project y RIPEstat. Complementa esta consulta con «Listas negras»,\n"
          . "que sondea las DNSBL de correo en tiempo real.\n";

    $bloques = [lg_block('rows', 'Veredicto', $rowsVer, $verSt)];
    $bloques[] = lg_block('rows', 'Historial de ataques observados', $rowsAtq,
        $iscReports > 0 ? 'warn' : 'good');
    $bloques[] = lg_block('rows', 'Listas de amenazas', $rowsAmz);
    if ($rowsRuta) {
        $bloques[] = lg_block('rows', 'Historial de enrutado (quien ha anunciado su red)', $rowsRuta);
    }

    return lg_ok(trim($out), $bloques, ['target' => $ip]);
}
