<?php
/**
 * Centinela - looking glass, herramientas avanzadas.
 *
 * Continuacion de lgtools.php: propagacion DNS, DNSSEC, Certificate
 * Transparency, entrega SMTP con DANE, MTU de la ruta y analisis de servidor.
 * Comparten los mismos ayudantes (lg_ok, lg_row, lg_block, lg_resolve,
 * lg_proc, lg_connect, lg_fetch_json, lg_feed) y las mismas reglas de
 * seguridad: lista blanca de destinos, sin shell, con timeout y sin exponer
 * nada del servidor que sirve la pagina.
 */

declare(strict_types=1);

/**
 * dig +short envolviendo el centinela «Sin salida.» que devuelve lg_proc
 * cuando no hay respuesta: sin esto, una consulta vacia parece tener datos.
 */
function lg_dig_short(string $type, string $name, string $resolver = '@1.1.1.1'): string
{
    $dig = bin_path('dig');
    if ($dig === null) {
        return '';
    }
    $out = trim(lg_proc([$dig, '+short', '+time=3', '+tries=2', $resolver, $name, $type], 8));
    if ($out === 'Sin salida.' || stripos($out, 'connection timed out') !== false) {
        return '';
    }
    return $out;
}

// ===========================================================================
// Propagacion DNS: el mismo registro visto por varios resolutores publicos
// ===========================================================================

/** Resolutores publicos con los que se contrasta. */
function lg_resolvers(): array
{
    return [
        '1.1.1.1'         => 'Cloudflare',
        '8.8.8.8'         => 'Google',
        '9.9.9.9'         => 'Quad9',
        '208.67.222.222'  => 'OpenDNS',
        '64.6.64.6'       => 'Verisign',
        '8.26.56.26'      => 'Comodo',
        '185.228.168.9'   => 'CleanBrowsing',
        '76.76.2.0'       => 'ControlD',
    ];
}

function lg_dnsprop(string $target, array $options): array
{
    $dig = bin_path('dig');
    if ($dig === null) {
        return lg_err('La herramienta dig no esta disponible en este servidor.');
    }
    $type = strtoupper((string) ($options['type'] ?? 'A'));
    if (!in_array($type, ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA', 'SRV', 'PTR', 'DS', 'DNSKEY'], true)) {
        $type = 'A';
    }
    $name = rtrim($target, '.');

    $rows = [];
    $huellas = [];   // respuesta normalizada => cuantos resolutores la dan
    foreach (lg_resolvers() as $ip => $nombre) {
        $out = lg_proc([$dig, '+short', '+time=2', '+tries=1', "@{$ip}", $name, $type], 6);
        $ans = array_values(array_filter(array_map('trim', explode("\n", trim($out)))));
        sort($ans);
        $resumen = $ans ? implode(' · ', array_slice($ans, 0, 4)) . (count($ans) > 4 ? ' …' : '') : '(sin respuesta)';
        $clave   = $ans ? implode('|', $ans) : '';
        if ($ans) {
            $huellas[$clave] = ($huellas[$clave] ?? 0) + 1;
        }
        $rows[] = lg_row($nombre, $resumen, '', $ip);
    }

    // Consenso: la respuesta mayoritaria. Cualquiera que difiera se marca.
    arsort($huellas);
    $consenso = array_key_first($huellas);
    $nDistintas = count($huellas);

    foreach ($rows as $i => $r) {
        // Reconstruimos la clave de cada fila para compararla con el consenso
        $ip = $r['note'];
        $out = lg_proc([$dig, '+short', '+time=2', '+tries=1', "@{$ip}", $name, $type], 4);
        $ans = array_values(array_filter(array_map('trim', explode("\n", trim($out)))));
        sort($ans);
        $clave = implode('|', $ans);
        if ($ans && $consenso !== null && $clave !== $consenso) {
            $rows[$i]['status'] = 'warn';
            $rows[$i]['note']  = $ip . ' · difiere del consenso';
        } elseif ($ans) {
            $rows[$i]['status'] = 'good';
        } else {
            $rows[$i]['status'] = 'warn';
        }
    }

    $estado = $nDistintas <= 1 ? 'good' : 'warn';
    $titulo = $nDistintas <= 1
        ? 'Propagado de forma consistente'
        : "Respuestas divergentes ({$nDistintas} versiones distintas)";

    $head = [
        lg_row('Registro', $name . ' ' . $type),
        lg_row('Coherencia', $titulo, $estado,
            $nDistintas <= 1 ? 'todos los resolutores coinciden'
                : 'un cambio a medio propagar, un DNS con geolocalizacion, o registros inconsistentes'),
    ];

    $out = "Propagacion de {$name} ({$type})\n" . str_repeat('-', 52) . "\n";
    foreach ($rows as $r) {
        $out .= sprintf("%-16s %-18s %s\n", $r['k'], $r['note'], $r['v']);
    }

    return lg_ok(trim($out), [
        lg_block('rows', 'Resumen', $head, $estado),
        lg_block('rows', 'Por resolutor', $rows),
    ], ['target' => $name]);
}

// ===========================================================================
// DNSSEC: valida la cadena de firmas y senala donde se rompe
// ===========================================================================

function lg_dnssec(string $target, array $options): array
{
    $dig = bin_path('dig');
    if ($dig === null) {
        return lg_err('La herramienta dig no esta disponible en este servidor.');
    }
    $name = rtrim(strtolower($target), '.');

    // 1) ¿El dominio esta firmado? Buscamos DNSKEY.
    $dnskey = lg_dig_short('DNSKEY', $name);
    $firmado = $dnskey !== '';

    // 2) ¿Existe el DS en la zona padre? Es el eslabon que ancla la confianza.
    $ds = lg_dig_short('DS', $name);

    // 3) ¿Un resolutor validador da por buena la respuesta? El flag AD lo dice.
    $adOut = lg_proc([$dig, '+dnssec', '+time=3', 'A', $name, '@1.1.1.1'], 8);
    $adFlag = (bool) preg_match('/flags:[^;]*\bad\b/', $adOut);

    // 4) delv hace la validacion criptografica completa si esta disponible.
    $delv = bin_path('delv');
    $delvVeredicto = '';
    if ($delv !== null) {
        $dout = lg_proc([$delv, '+time=4', '@1.1.1.1', $name, 'A'], 12);
        if (str_contains($dout, 'fully validated')) {
            $delvVeredicto = 'validado';
        } elseif (preg_match('/resolution failed: (\S+)/', $dout, $m)) {
            $delvVeredicto = 'fallo: ' . $m[1];
        } elseif (str_contains($dout, 'unsigned answer')) {
            $delvVeredicto = 'sin firmar';
        }
    }

    $rows = [
        lg_row('Zona firmada (DNSKEY)', $firmado ? 'si' : 'no',
            $firmado ? 'good' : 'warn',
            $firmado ? '' : 'el dominio no usa DNSSEC: sus respuestas no se pueden autenticar'),
        lg_row('Anclaje en el padre (DS)', $ds !== '' ? 'presente' : 'ausente',
            $firmado ? ($ds !== '' ? 'good' : 'crit') : '',
            $firmado && $ds === '' ? 'firmado pero sin DS: la cadena de confianza no llega desde la raiz' : ''),
        lg_row('Validado por el resolutor (AD)', $adFlag ? 'si' : 'no',
            $firmado ? ($adFlag ? 'good' : 'crit') : '',
            $firmado && !$adFlag ? 'un validador NO da por buena la firma: posible DNSSEC roto (bogus)' : ''),
    ];
    if ($delvVeredicto !== '') {
        $rows[] = lg_row('Validacion criptografica (delv)', $delvVeredicto,
            $delvVeredicto === 'validado' ? 'good' : ($delvVeredicto === 'sin firmar' ? '' : 'crit'));
    }

    // Veredicto y donde se rompe
    if (!$firmado) {
        $verSt = 'warn';
        $verTx = 'Sin DNSSEC';
        $expl  = 'El dominio no esta firmado. No es un fallo, pero sus registros viajan sin proteccion '
               . 'contra manipulacion en el camino.';
    } elseif ($ds === '') {
        $verSt = 'crit';
        $verTx = 'Firmado pero sin anclar';
        $expl  = 'La zona tiene firmas pero el registro DS no esta publicado en la zona padre. La cadena '
               . 'de confianza se rompe ahi: publica el DS en tu registrador.';
    } elseif (!$adFlag || $delvVeredicto === 'fallo') {
        $verSt = 'crit';
        $verTx = 'DNSSEC roto (bogus)';
        $expl  = 'Hay DS y DNSKEY pero la validacion falla. Suele ser una rotacion de claves mal hecha o '
               . 'firmas caducadas: muchos resolutores rechazaran el dominio por completo.';
    } else {
        $verSt = 'good';
        $verTx = 'Cadena DNSSEC integra';
        $expl  = 'Desde la raiz hasta el dominio, cada eslabon firma al siguiente y la validacion es correcta.';
    }

    $out = "DNSSEC de {$name}\n" . str_repeat('-', 52) . "\n"
         . "Veredicto: {$verTx}\n{$expl}\n\n";
    foreach ($rows as $r) {
        $out .= sprintf("%-32s %s\n", $r['k'] . ':', $r['v']);
    }

    return lg_ok(trim($out), [
        lg_block('rows', 'Veredicto: ' . $verTx, array_merge(
            [lg_row('Diagnostico', $expl, $verSt)], $rows), $verSt),
    ], ['target' => $name]);
}

// ===========================================================================
// Certificate Transparency: todo certificado emitido para un dominio
// ===========================================================================

function lg_crt(string $target, array $options): array
{
    $name = rtrim(strtolower($target), '.');
    if (filter_var($name, FILTER_VALIDATE_IP)) {
        return lg_err('Indica un dominio, no una direccion IP.');
    }

    // crt.sh publica los registros de Certificate Transparency, pero su API se
    // sobrecarga y responde 502 a menudo. Reintentamos un par de veces, y con
    // dos formas de consulta: comodin (mas completa) e identidad (mas ligera).
    $data = null;
    $urls = [
        'https://crt.sh/?q=' . rawurlencode('%.' . $name) . '&output=json&exclude=expired',
        'https://crt.sh/?q=' . rawurlencode($name) . '&output=json&exclude=expired',
    ];
    foreach ($urls as $u) {
        for ($intento = 0; $intento < 2 && !is_array($data); $intento++) {
            $data = lg_fetch_json($u, 8, 12582912);
            if (!is_array($data) && $intento === 0) {
                usleep(400000);   // respiro corto antes de reintentar
            }
        }
        if (is_array($data)) {
            break;
        }
    }
    if (!is_array($data)) {
        return lg_err('crt.sh no responde ahora mismo (suele dar 502 cuando esta saturado). Reintenta en unos segundos.');
    }

    $nombres  = [];   // subdominio => ['first'=>ts, 'issuers'=>set]
    $issuers  = [];
    $reciente = [];
    $corte    = time() - 7 * 86400;

    foreach ($data as $c) {
        $issuer = trim((string) ($c['issuer_name'] ?? ''));
        if (preg_match('/O=([^,]+)/', $issuer, $m)) {
            $issuers[trim($m[1])] = ($issuers[trim($m[1])] ?? 0) + 1;
        }
        foreach (explode("\n", (string) ($c['name_value'] ?? '')) as $n) {
            $n = strtolower(trim($n));
            if ($n === '' || str_starts_with($n, '*')) {
                if ($n === '') {
                    continue;
                }
            }
            if ($n !== '' && (str_ends_with($n, $name) || $n === $name)) {
                if (!isset($nombres[$n])) {
                    $nombres[$n] = true;
                }
            }
        }
        $ts = strtotime((string) ($c['not_before'] ?? ''));
        if ($ts && $ts >= $corte) {
            $reciente[] = [
                'name' => trim((string) ($c['common_name'] ?? '')),
                'ca'   => preg_match('/O=([^,]+)/', $issuer, $mm) ? trim($mm[1]) : $issuer,
                'date' => date('Y-m-d', $ts),
            ];
        }
    }
    ksort($nombres);
    arsort($issuers);

    // Comprobamos cuales de esos nombres siguen resolviendo: los que no, son
    // subdominios olvidados con certificado emitido, y una pista para atacantes.
    $vivos = $muertos = [];
    $comprobar = array_slice(array_keys($nombres), 0, 60);
    foreach ($comprobar as $n) {
        if (str_contains($n, '*')) {
            continue;
        }
        $ok = @dns_get_record($n, DNS_A) || @dns_get_record($n, DNS_AAAA) || @dns_get_record($n, DNS_CNAME);
        if ($ok) {
            $vivos[] = $n;
        } else {
            $muertos[] = $n;
        }
    }

    $rowsResumen = [
        lg_row('Nombres distintos', (string) count($nombres), '', 'subdominios que han tenido certificado'),
        lg_row('Autoridades emisoras', implode(', ', array_slice(array_keys($issuers), 0, 4)) ?: '—'),
        lg_row('Certificados en 7 dias', (string) count($reciente),
            count($reciente) > 0 ? 'warn' : '',
            count($reciente) > 0 ? 'emision reciente: legitima si la reconoces, sospechosa si no' : ''),
        lg_row('Subdominios que ya no resuelven', (string) count($muertos),
            count($muertos) > 0 ? 'warn' : 'good',
            count($muertos) > 0 ? 'tienen cert emitido pero no apuntan a nada: candidatos a takeover' : ''),
    ];

    $bloques = [lg_block('rows', 'Resumen', $rowsResumen)];

    if ($reciente) {
        usort($reciente, fn($a, $b) => strcmp($b['date'], $a['date']));
        $rr = [];
        foreach (array_slice($reciente, 0, 12) as $c) {
            $rr[] = lg_row($c['date'], $c['name'], '', $c['ca']);
        }
        $bloques[] = lg_block('rows', 'Emitidos en los ultimos 7 dias', $rr, 'warn');
    }

    if ($vivos) {
        $bloques[] = lg_block('tags', 'Subdominios activos vistos en CT (' . count($vivos) . ')',
            array_slice($vivos, 0, 40));
    }
    if ($muertos) {
        $bloques[] = lg_block('tags', 'Con certificado pero sin DNS (' . count($muertos) . ')',
            array_slice($muertos, 0, 30));
    }

    $out = "Certificate Transparency de {$name}\n" . str_repeat('-', 52) . "\n"
         . 'Nombres distintos: ' . count($nombres) . "\n"
         . 'Emisoras: ' . implode(', ', array_slice(array_keys($issuers), 0, 5)) . "\n"
         . 'Certificados en 7 dias: ' . count($reciente) . "\n"
         . 'Subdominios sin DNS: ' . count($muertos) . "\n\n"
         . "Subdominios activos:\n  " . implode("\n  ", array_slice($vivos, 0, 40)) . "\n\n"
         . "Fuente: crt.sh (logs de Certificate Transparency). Util para descubrir\n"
         . "subdominios olvidados y detectar certificados que no autorizaste.\n";

    return lg_ok(trim($out), $bloques, ['target' => $name]);
}

// ===========================================================================
// Entrega SMTP: conexion real a cada MX, STARTTLS, certificado y DANE
// ===========================================================================

function lg_smtp(string $target, array $options): array
{
    $domain = rtrim(strtolower($target), '.');
    if (filter_var($domain, FILTER_VALIDATE_IP)) {
        return lg_err('Indica un dominio de correo, no una IP.');
    }

    $mx = [];
    foreach (@dns_get_record($domain, DNS_MX) ?: [] as $r) {
        $mx[] = ['host' => rtrim((string) $r['target'], '.'), 'pri' => (int) ($r['pri'] ?? 0)];
    }
    usort($mx, fn($a, $b) => $a['pri'] <=> $b['pri']);
    if (!$mx) {
        return lg_err('El dominio no tiene registros MX: no puede recibir correo.');
    }

    $bloques = [];
    $out = "Entrega SMTP de {$domain}\n" . str_repeat('-', 52) . "\n";

    foreach (array_slice($mx, 0, 3) as $m) {
        $host = $m['host'];
        $res  = lg_resolve($host);
        if (!$res['ok']) {
            $bloques[] = lg_block('rows', $host, [lg_row('Resolucion', 'fallo: ' . $res['error'], 'crit')], 'crit');
            continue;
        }
        $ip = $res['ip'];

        $meta = [];
        $sock = lg_connect($ip, 25, null, false, 8.0, $meta);
        $rows = [lg_row('Prioridad / IP', $m['pri'] . ' · ' . $ip)];

        if ($sock === null) {
            $rows[] = lg_row('Conexion al 25', 'sin respuesta', 'crit',
                $meta['error'] ?? 'el puerto SMTP no acepta conexiones desde aqui');
            $bloques[] = lg_block('rows', $host, $rows, 'crit');
            $out .= "\n{$host}: no responde en el puerto 25\n";
            continue;
        }

        stream_set_timeout($sock, 8);
        $saludo = lg_smtp_read($sock);
        $rows[] = lg_row('Saludo', mb_strimwidth(trim($saludo), 0, 60, '…'),
            str_starts_with($saludo, '220') ? 'good' : 'warn');

        // EHLO y capacidades
        fwrite($sock, "EHLO looking-glass.centinela\r\n");
        $ehlo = lg_smtp_read($sock);
        $tieneTls  = stripos($ehlo, 'STARTTLS') !== false;
        $tamano    = preg_match('/SIZE (\d+)/i', $ehlo, $ms) ? (int) $ms[1] : 0;
        $rows[] = lg_row('STARTTLS ofrecido', $tieneTls ? 'si' : 'no',
            $tieneTls ? 'good' : 'crit',
            $tieneTls ? '' : 'sin cifrado: el correo entrante viaja en claro');
        if ($tamano > 0) {
            $rows[] = lg_row('Tamano maximo', lg_bytes_human($tamano));
        }

        // STARTTLS: subimos a TLS sobre la misma conexion y miramos el cert
        if ($tieneTls) {
            fwrite($sock, "STARTTLS\r\n");
            $stls = lg_smtp_read($sock);
            if (str_starts_with($stls, '220')) {
                stream_context_set_option($sock, 'ssl', 'verify_peer', false);
                stream_context_set_option($sock, 'ssl', 'verify_peer_name', false);
                stream_context_set_option($sock, 'ssl', 'capture_peer_cert', true);
                stream_context_set_option($sock, 'ssl', 'SNI_enabled', true);
                stream_context_set_option($sock, 'ssl', 'peer_name', $host);
                @stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                $params = stream_context_get_params($sock);
                $cert = $params['options']['ssl']['peer_certificate'] ?? null;
                if ($cert) {
                    $info = openssl_x509_parse($cert);
                    $cn = $info['subject']['CN'] ?? '(sin CN)';
                    $exp = isset($info['validTo_time_t']) ? date('Y-m-d', $info['validTo_time_t']) : '?';
                    $venc = isset($info['validTo_time_t']) && $info['validTo_time_t'] < time();
                    $rows[] = lg_row('Certificado TLS', $cn, $venc ? 'crit' : 'good', 'caduca ' . $exp);
                    // ¿El nombre del MX esta cubierto por el certificado?
                    $cubre = lg_cert_cubre($info, $host);
                    $rows[] = lg_row('Cubre el nombre del MX', $cubre ? 'si' : 'no',
                        $cubre ? 'good' : 'warn',
                        $cubre ? '' : 'el cert no incluye ' . $host . ': validacion estricta fallaria');
                }
            }
        }

        // DANE: el registro TLSA ata el certificado esperado en el DNS firmado
        $tlsa = lg_dig_short('TLSA', "_25._tcp.{$host}");
        $rows[] = lg_row('DANE (TLSA)', $tlsa !== '' ? 'publicado' : 'ausente',
            $tlsa !== '' ? 'good' : '',
            $tlsa !== '' ? 'el certificado esperado esta anclado en DNSSEC' : 'sin DANE (habitual, no es un fallo)');

        @fwrite($sock, "QUIT\r\n");
        @fclose($sock);

        $peor = 'good';
        foreach ($rows as $r) {
            if (($r['status'] ?? '') === 'crit') { $peor = 'crit'; break; }
            if (($r['status'] ?? '') === 'warn') { $peor = 'warn'; }
        }
        $bloques[] = lg_block('rows', $host, $rows, $peor);
        $out .= "\n{$host} ({$ip}) prioridad {$m['pri']}\n"
              . '  STARTTLS: ' . ($tieneTls ? 'si' : 'NO') . ' · DANE: ' . ($tlsa !== '' ? 'si' : 'no') . "\n";
    }

    if (count($mx) > 3) {
        $out .= "\n(" . (count($mx) - 3) . ' MX adicionales no sondeados)' . "\n";
    }

    return lg_ok(trim($out), $bloques, ['target' => $domain]);
}

/** Lee una respuesta SMTP completa (varias lineas «250-…» hasta «250 …»). */
function lg_smtp_read($sock): string
{
    $out = '';
    $fin = microtime(true) + 6;
    while (microtime(true) < $fin) {
        $line = fgets($sock, 1024);
        if ($line === false) {
            break;
        }
        $out .= $line;
        // Ultima linea: codigo seguido de espacio, no de guion
        if (preg_match('/^\d{3} /m', $line)) {
            break;
        }
    }
    return $out;
}

/** ¿El certificado (parseado) cubre este nombre, incluidos comodines? */
function lg_cert_cubre(array $info, string $host): bool
{
    $nombres = [];
    if (!empty($info['subject']['CN'])) {
        $nombres[] = strtolower($info['subject']['CN']);
    }
    $san = $info['extensions']['subjectAltName'] ?? '';
    foreach (explode(',', $san) as $x) {
        $x = trim($x);
        if (stripos($x, 'DNS:') === 0) {
            $nombres[] = strtolower(substr($x, 4));
        }
    }
    $host = strtolower($host);
    foreach ($nombres as $n) {
        if ($n === $host) {
            return true;
        }
        if (str_starts_with($n, '*.') && str_ends_with($host, substr($n, 1))
            && substr_count($host, '.') === substr_count($n, '.')) {
            return true;
        }
    }
    return false;
}

/** Bytes a unidades legibles (local, sin depender del colector). */
function lg_bytes_human(int $b): string
{
    $u = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    while ($b >= 1024 && $i < 3) { $b = intdiv($b, 1024); $i++; }
    return $b . ' ' . $u[$i];
}

// ===========================================================================
// MTU de la ruta: mayor paquete que llega sin fragmentar
// ===========================================================================

function lg_mtu(string $target, array $options): array
{
    $ping = bin_path('ping');
    if ($ping === null) {
        return lg_err('La herramienta ping no esta disponible.');
    }
    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip = $res['ip'];
    $v6 = str_contains($ip, ':');
    // Cabeceras: IPv4 20+8 ICMP, IPv6 40+8. El payload + cabeceras = MTU.
    $overhead = $v6 ? 48 : 28;

    // Busqueda binaria del mayor payload que pasa con «no fragmentar».
    $lo = 0;                    // seguro (0 bytes siempre pasa)
    $hi = $v6 ? 8952 : 9000;    // techo (jumbo frames)
    $mejor = 0;
    $localMtu = 0;
    $iter = 0;

    while ($lo <= $hi && $iter < 16) {
        $iter++;
        $mid = intdiv($lo + $hi, 2);
        $cmd = $v6
            ? [$ping, '-6', '-c', '1', '-W', '2', '-M', 'do', '-s', (string) $mid, '-n', '--', $ip]
            : [$ping, '-c', '1', '-W', '2', '-M', 'do', '-s', (string) $mid, '-n', '--', $ip];
        $out = lg_proc($cmd, 5);

        // El propio enlace local puede ser el limite: ping lo dice explicito.
        if (preg_match('/local error:.*mtu=(\d+)/', $out, $m)) {
            $localMtu = (int) $m[1];
            $hi = min($hi, $localMtu - $overhead);
            continue;
        }
        $paso = (bool) preg_match('/\b1 received|bytes from/', $out) && !preg_match('/0 received/', $out);
        if ($paso) {
            $mejor = $mid;
            $lo = $mid + 1;
        } else {
            $hi = $mid - 1;
        }
    }

    $pmtu = $mejor + $overhead;
    $rows = [
        lg_row('Destino', $ip . ($res['resolved'] && $res['resolved'][0] !== $ip ? ' (' . $target . ')' : '')),
        lg_row('MTU de la ruta', $mejor > 0 ? $pmtu . ' bytes' : 'no determinada',
            $mejor > 0 ? 'good' : 'warn'),
        lg_row('Payload maximo sin fragmentar', $mejor > 0 ? $mejor . ' bytes' : '—'),
    ];
    if ($localMtu > 0) {
        $rows[] = lg_row('MTU del enlace local', $localMtu . ' bytes', '',
            $localMtu < 1500 ? 'este servidor sale por un enlace de MTU reducida (PPPoE, tunel)' : '');
    }

    // Lecturas utiles para un ingeniero
    if ($mejor > 0) {
        if ($pmtu >= 1500) {
            $rows[] = lg_row('Lectura', 'Ethernet estandar (1500). Ruta limpia sin tuneles que recorten.', 'good');
        } elseif ($pmtu >= 1492) {
            $rows[] = lg_row('Lectura', 'Tipico de PPPoE (1492). Normal en accesos DSL/fibra domesticos.', 'good');
        } elseif ($pmtu >= 1400) {
            $rows[] = lg_row('Lectura', 'Recortada: hay un tunel en el camino (VPN, GRE, IPsec).', 'warn',
                'si algun servicio da timeouts raros, puede ser PMTU: fija MSS clamping');
        } else {
            $rows[] = lg_row('Lectura', 'MTU muy baja (' . $pmtu . '). Probable tunel sobre tunel o problema de red.', 'warn');
        }
    }

    $out = "MTU de la ruta hasta {$ip}\n" . str_repeat('-', 52) . "\n";
    foreach ($rows as $r) {
        $out .= sprintf("%-32s %s\n", $r['k'] . ':', $r['v']);
    }
    $out .= "\nMedido con paquetes ICMP marcados «no fragmentar» y busqueda binaria.\n"
          . "La MTU efectiva es el menor enlace de todo el camino.\n";

    return lg_ok(trim($out), [lg_block('rows', 'MTU de la ruta', $rows,
        $mejor > 0 ? 'good' : 'warn')], ['target' => $ip]);
}

// ===========================================================================
// Analisis de servidor: web, panel, CMS, version y CVE conocidos
// ===========================================================================

/** GET HTTP sencillo sobre la conexion segura del looking glass. */
function lg_http_get(string $ip, string $host, bool $tls, string $path = '/', int $timeout = 8): array
{
    $meta = [];
    $sock = lg_connect($ip, $tls ? 443 : 80, $tls && !filter_var($host, FILTER_VALIDATE_IP) ? $host : null, $tls, (float) $timeout, $meta);
    if ($sock === null) {
        return ['ok' => false, 'status' => 0, 'headers' => [], 'body' => ''];
    }
    $req = "GET {$path} HTTP/1.1\r\nHost: {$host}\r\n"
         . "User-Agent: Centinela-LookingGlass/1.0 (+diagnostico)\r\n"
         . "Accept: text/html,*/*\r\nConnection: close\r\n\r\n";
    fwrite($sock, $req);
    $raw = '';
    $deadline = microtime(true) + $timeout;
    stream_set_timeout($sock, $timeout);
    while (!feof($sock) && microtime(true) < $deadline && strlen($raw) < 262144) {
        $chunk = fread($sock, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $raw .= $chunk;
    }
    @fclose($sock);

    $parts = explode("\r\n\r\n", $raw, 2);
    $head  = $parts[0] ?? '';
    $body  = $parts[1] ?? '';
    $status = 0;
    if (preg_match('#HTTP/\d\.\d (\d{3})#', $head, $m)) {
        $status = (int) $m[1];
    }
    $headers = [];
    foreach (explode("\r\n", $head) as $line) {
        if (str_contains($line, ':')) {
            [$k, $v] = explode(':', $line, 2);
            $headers[strtolower(trim($k))] = trim($v);
        }
    }
    // Cuerpo troceado (Transfer-Encoding: chunked): desandar por encima
    if (stripos($headers['transfer-encoding'] ?? '', 'chunked') !== false) {
        $body = preg_replace('/^[0-9a-fA-F]+\r\n/m', '', $body) ?? $body;
    }
    return ['ok' => true, 'status' => $status, 'headers' => $headers, 'body' => substr($body, 0, 200000)];
}

function lg_fingerprint(string $target, array $options): array
{
    $res = lg_resolve($target);
    if (!$res['ok']) {
        return lg_err($res['error']);
    }
    $ip   = $res['ip'];
    $host = filter_var($target, FILTER_VALIDATE_IP) ? $ip : rtrim(strtolower($target), '.');

    $r = lg_http_get($ip, $host, true, '/', 8);
    if (!$r['ok']) {
        $r = lg_http_get($ip, $host, false, '/', 8);
    }
    if (!$r['ok']) {
        return lg_err('No se pudo conectar a ' . $host . ' por HTTP/HTTPS.');
    }
    $h    = $r['headers'];
    $body = $r['body'];

    $detectado = [];   // [categoria, producto, version|'', pista]

    // ---- servidor web ----------------------------------------------------
    $server = $h['server'] ?? '';
    if ($server !== '') {
        if (preg_match('#([a-zA-Z-]+)/([\d.]+)#', $server, $m)) {
            $detectado[] = ['Servidor web', $m[1], $m[2], 'cabecera Server'];
        } else {
            $detectado[] = ['Servidor web', $server, '', 'cabecera Server'];
        }
    }
    $powered = $h['x-powered-by'] ?? '';
    if (preg_match('/PHP\/([\d.]+)/i', $powered, $m)) {
        $detectado[] = ['Lenguaje', 'PHP', $m[1], 'cabecera X-Powered-By'];
    }

    // ---- panel de control ------------------------------------------------
    $panel = null;
    $cookies = strtolower(implode(' ', array_filter([$h['set-cookie'] ?? ''])));
    if (str_contains($server, 'cpsrvd') || isset($h['x-cpanel-error']) || str_contains($cookies, 'cpsession')) {
        $panel = ['cPanel', ''];
    } elseif (stripos($server, 'sw-cp-server') !== false || lg_tcp_abierto($ip, 8443)) {
        $panel = ['Plesk', ''];
        if (lg_tcp_abierto($ip, 8880)) { $panel[1] = ''; }
    } elseif (lg_tcp_abierto($ip, 8083)) {
        $panel = ['HestiaCP / VestaCP', ''];
    } elseif (lg_tcp_abierto($ip, 2222)) {
        $panel = ['DirectAdmin', ''];
    } elseif (lg_tcp_abierto($ip, 10000)) {
        $panel = ['Webmin', ''];
    }
    if ($panel) {
        $detectado[] = ['Panel de control', $panel[0], $panel[1], 'huella de red'];
    }

    // ---- CMS -------------------------------------------------------------
    $cms = null; $cmsVer = '';
    if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
        $gen = $m[1];
        if (preg_match('/(WordPress|Joomla|Drupal|TYPO3|PrestaShop|Ghost|Magento)[\s!]*([\d.]*)/i', $gen, $mm)) {
            $cms = ucfirst(strtolower($mm[1])); $cmsVer = $mm[2];
        } else {
            $detectado[] = ['Generador', $gen, '', 'meta generator'];
        }
    }
    if ($cms === null) {
        if (str_contains($body, '/wp-content/') || str_contains($body, '/wp-includes/')
            || isset($h['link']) && str_contains($h['link'], 'wp-json')) {
            $cms = 'WordPress';
        } elseif (str_contains($body, '/sites/all/') || str_contains($body, 'Drupal.settings')) {
            $cms = 'Drupal';
        } elseif (str_contains($body, '/media/jui/') || stripos($body, 'joomla') !== false) {
            $cms = 'Joomla';
        } elseif (str_contains($body, 'cdn.shopify.com')) {
            $cms = 'Shopify';
        }
    }
    // Version de WordPress por el readme si la portada no la delata
    if ($cms === 'WordPress' && $cmsVer === '') {
        $rm = lg_http_get($ip, $host, ($r['status'] ?? 0) > 0, '/readme.html', 6);
        if (preg_match('/Version\s+([\d.]+)/i', $rm['body'] ?? '', $mm)) {
            $cmsVer = $mm[1];
        }
    }
    if ($cms !== null) {
        $detectado[] = ['CMS', $cms, $cmsVer, $cmsVer !== '' ? 'version detectada' : 'huellas en el HTML'];
    }

    // ---- estado de soporte (endoflife.date) para lo que tenga version ----
    $eolMap = ['nginx' => 'nginx', 'apache' => 'apache', 'php' => 'php',
               'wordpress' => 'wordpress', 'drupal' => 'drupal', 'joomla' => 'joomla'];
    $avisos = [];
    foreach ($detectado as &$d) {
        $prodKey = strtolower(explode(' ', $d[1])[0]);
        if ($d[2] !== '' && isset($eolMap[$prodKey])) {
            $eol = lg_eol_estado($eolMap[$prodKey], $d[2]);
            if ($eol !== null) {
                $d[3] .= ' · ' . $eol['txt'];
                if ($eol['eol']) {
                    $avisos[] = [$d[1] . ' ' . $d[2], $eol['txt']];
                }
            }
        }
    }
    unset($d);

    // ---- CVE conocidos del producto principal (CIRCL) --------------------
    $cves = [];
    $consulta = null;
    if ($cms !== null) {
        $consulta = [strtolower($cms), strtolower($cms)];
    } elseif ($panel) {
        $consulta = [strtolower(explode(' ', $panel[0])[0]), strtolower(explode(' ', $panel[0])[0])];
    }
    if ($consulta) {
        $cj = lg_fetch_json('https://cve.circl.lu/api/search/' . rawurlencode($consulta[0]) . '/' . rawurlencode($consulta[1]), 12, 4194304);
        $lista = $cj['results']['nvd'] ?? ($cj['results'] ?? []);
        $n = 0;
        foreach ((array) $lista as $item) {
            $rec = is_array($item) && isset($item[1]) ? $item[1] : $item;
            $id = $rec['cveMetadata']['cveId'] ?? ($rec['id'] ?? '');
            if ($id === '') { continue; }
            $desc = '';
            $cna = $rec['containers']['cna'] ?? [];
            foreach ((array) ($cna['descriptions'] ?? []) as $dsc) {
                if (($dsc['lang'] ?? '') === 'en') { $desc = $dsc['value']; break; }
            }
            $cves[] = ['id' => $id, 'desc' => mb_strimwidth(trim($desc), 0, 100, '…')];
            if (++$n >= 8) { break; }
        }
    }

    // ---- montaje de la respuesta ----------------------------------------
    $rowsId = [lg_row('Direccion', $ip)];
    foreach ($detectado as $d) {
        $val = $d[1] . ($d[2] !== '' ? ' ' . $d[2] : '');
        $rowsId[] = lg_row($d[0], $val, '', $d[3]);
    }
    if (!$detectado) {
        $rowsId[] = lg_row('Huella', 'poco reveladora', 'good',
            'el servidor no anuncia su software: buena practica de fortificacion');
    }

    $bloques = [lg_block('rows', 'Identificacion', $rowsId)];

    if ($avisos) {
        $rw = [];
        foreach ($avisos as $a) {
            $rw[] = lg_row($a[0], $a[1], 'crit');
        }
        $bloques[] = lg_block('rows', 'Versiones sin soporte', $rw, 'crit');
    }

    if ($cves) {
        $tags = array_map(fn($c) => $c['id'], $cves);
        $bloques[] = lg_block('tags', 'CVE conocidos de ' . ($cms ?? $panel[0]) . ' (verifica si aplican a esta version)', $tags);
        $rwc = [];
        foreach (array_slice($cves, 0, 5) as $c) {
            $rwc[] = lg_row($c['id'], $c['desc']);
        }
        $bloques[] = lg_block('rows', 'Detalle de vulnerabilidades', $rwc, 'warn');
    }

    // Exposiciones concretas que si podemos afirmar
    $exp = [];
    if ($panel && in_array($panel[0], ['Webmin'], true)) {
        $exp[] = 'El panel ' . $panel[0] . ' expone su puerto de administracion a internet.';
    }
    if ($cms === 'WordPress') {
        $wl = lg_http_get($ip, $host, ($r['status'] ?? 0) > 0, '/wp-login.php', 6);
        if (($wl['status'] ?? 0) === 200) {
            $exp[] = 'wp-login.php es accesible: objetivo de fuerza bruta. Conviene limitarlo o protegerlo.';
        }
    }
    if ($exp) {
        $bloques[] = lg_block('tags', 'Exposiciones observadas', $exp);
    }

    $out = "Analisis de {$host} ({$ip})\n" . str_repeat('-', 52) . "\n";
    foreach ($detectado as $d) {
        $out .= sprintf("%-18s %s %s\n", $d[0] . ':', $d[1], $d[2]);
    }
    if ($avisos) {
        $out .= "\nVersiones sin soporte:\n";
        foreach ($avisos as $a) { $out .= '  - ' . $a[0] . ': ' . $a[1] . "\n"; }
    }
    if ($cves) {
        $out .= "\nCVE conocidos de " . ($cms ?? $panel[0]) . ":\n";
        foreach ($cves as $c) { $out .= '  ' . $c['id'] . '  ' . $c['desc'] . "\n"; }
        $out .= "  (son CVE del producto; verifica si afectan a la version concreta)\n";
    }
    $out .= "\nFuentes: cabeceras y HTML del sitio, huella de puertos, endoflife.date\n"
          . "(soporte de versiones) y CIRCL cve.circl.lu (CVE). El fingerprinting es\n"
          . "orientativo: un buen servidor oculta o falsea estas pistas.\n";

    return lg_ok(trim($out), $bloques, ['target' => $host]);
}

/** ¿Hay algo escuchando en ese puerto TCP? Prueba corta, para huella de panel. */
function lg_tcp_abierto(string $ip, int $port): bool
{
    $h = str_contains($ip, ':') ? "[{$ip}]" : $ip;
    $s = @stream_socket_client("tcp://{$h}:{$port}", $e, $es, 2.5);
    if ($s) { fclose($s); return true; }
    return false;
}

/** Estado de soporte de una version segun endoflife.date. */
function lg_eol_estado(string $producto, string $version): ?array
{
    $data = lg_feed('eol_' . $producto, 'https://endoflife.date/api/' . $producto . '.json', 86400, 262144);
    $ciclos = json_decode((string) $data, true);
    if (!is_array($ciclos)) {
        return null;
    }
    // El ciclo es el prefijo mayor.menor de la version detectada
    $mm = implode('.', array_slice(explode('.', $version), 0, 2));
    foreach ($ciclos as $c) {
        $cyc = (string) ($c['cycle'] ?? '');
        if ($cyc === $mm || $cyc === explode('.', $version)[0]) {
            $eol = $c['eol'] ?? false;
            if ($eol === true || (is_string($eol) && strtotime($eol) !== false && strtotime($eol) < time())) {
                return ['eol' => true, 'txt' => 'sin soporte' . (is_string($eol) ? ' desde ' . $eol : '')];
            }
            return ['eol' => false, 'txt' => 'con soporte'];
        }
    }
    return null;
}

// ===========================================================================
// Latencia desde varias regiones (sondas globales de globalping.io)
// ===========================================================================

/**
 * Un ping/traceroute no puede salir de mas de un sitio: este servidor esta
 * donde esta. Para ver la red desde fuera se usan las sondas comunitarias de
 * globalping.io (jsDelivr), un servicio publico sin clave de API, igual que el
 * resto del looking glass. Sirve para lo que pregunta el ingeniero: «¿mi red
 * es alcanzable desde todas partes, o hay una region a la que le falla el
 * enrutado?».
 */

/** POST JSON con el contexto de flujo estandar (no hay curl garantizado). */
function lg_post_json(string $url, array $payload, int $timeout = 12): ?array
{
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
    $ctx = stream_context_create([
        'http' => [
            'method'  => 'POST',
            'timeout' => $timeout,
            'header'  => "Content-Type: application/json\r\n"
                       . "Accept: application/json\r\n"
                       . "User-Agent: Centinela-LookingGlass/1.0\r\n",
            'content' => $body,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
    ]);
    $resp = @file_get_contents($url, false, $ctx, 0, 1048576);
    if ($resp === false) {
        return null;
    }
    $d = json_decode($resp, true);
    return is_array($d) ? $d : null;
}

function lg_geoping(string $target, array $options): array
{
    $name = trim($target);

    // Un puñado de regiones repartidas por el mundo: una sonda por continente.
    // globalping devuelve una sonda por cada entrada de «locations».
    $regiones = [
        ['continent' => 'EU'], ['continent' => 'NA'], ['continent' => 'SA'],
        ['continent' => 'AS'], ['continent' => 'OC'], ['continent' => 'AF'],
    ];

    $crear = lg_post_json('https://api.globalping.io/v1/measurements', [
        'type'    => 'ping',
        'target'  => $name,
        'inProgressUpdates' => false,
        'locations' => $regiones,
        'measurementOptions' => ['packets' => 4],
    ], 12);

    if (!is_array($crear) || empty($crear['id'])) {
        $msg = is_array($crear) && !empty($crear['error']['message'])
            ? $crear['error']['message']
            : 'no se pudo crear la medida (globalping.io puede estar limitando por trafico)';
        return lg_err('Medicion global no disponible: ' . $msg);
    }
    $id = (string) $crear['id'];

    // La medida es asincrona: se sondea hasta que termina o se agota el tiempo.
    $res = null;
    $fin = microtime(true) + 22;
    while (microtime(true) < $fin) {
        usleep(1500000);
        $res = lg_fetch_json('https://api.globalping.io/v1/measurements/' . $id, 8);
        if (is_array($res) && ($res['status'] ?? '') === 'finished') {
            break;
        }
    }
    if (!is_array($res) || empty($res['results'])) {
        return lg_err('La medicion global no ha terminado a tiempo. Reintenta en un momento.');
    }

    $rows = [];
    $latencias = [];
    $fallos = 0;
    $completas = 0;

    foreach ($res['results'] as $r) {
        $p   = $r['probe'] ?? [];
        $rr  = $r['result'] ?? [];
        $cc  = strtoupper((string) ($p['country'] ?? '??'));
        $ciudad = (string) ($p['city'] ?? '');
        $red = (string) ($p['network'] ?? '');
        $etiqueta = trim($ciudad . ($cc ? ', ' . $cc : ''));

        $stats = $rr['stats'] ?? [];
        $avg   = $stats['avg'] ?? null;
        $loss  = $stats['loss'] ?? null;

        if ($avg === null || $loss === 100) {
            $fallos++;
            $rows[] = lg_row($etiqueta ?: 'sonda',
                $loss === 100 ? 'INALCANZABLE (100% perdida)' : 'sin respuesta',
                'crit', mb_strimwidth($red, 0, 34, '…'));
        } else {
            $completas++;
            $latencias[] = (float) $avg;
            $st = $loss > 0 ? 'warn' : 'good';
            $txt = round((float) $avg, 1) . ' ms'
                 . ($loss > 0 ? ' · ' . round((float) $loss) . '% perdida' : '');
            $rows[] = lg_row($etiqueta ?: 'sonda', $txt, $st, mb_strimwidth($red, 0, 34, '…'));
        }
    }

    // Ordenamos por latencia, dejando los fallos al final
    usort($rows, function ($a, $b) {
        $fa = str_contains($a['v'], 'ms') ? (float) $a['v'] : INF;
        $fb = str_contains($b['v'], 'ms') ? (float) $b['v'] : INF;
        return $fa <=> $fb;
    });

    // Veredicto orientado al diagnostico de enrutado
    if ($fallos > 0 && $completas > 0) {
        $verSt = 'crit';
        $verTx = $fallos . ' de ' . ($fallos + $completas) . ' regiones NO alcanzan el destino';
        $expl  = 'Es alcanzable desde unas regiones pero no desde otras: apunta a un problema de enrutado '
               . '(una ruta retirada, un filtrado geografico o un secuestro de prefijo), no a una caida del '
               . 'servidor. Lanza un traceroute desde la region que falla para ver donde muere.';
    } elseif ($fallos > 0) {
        $verSt = 'crit';
        $verTx = 'No responde desde ninguna sonda';
        $expl  = 'El destino no contesta a ICMP desde ningun sitio: o esta caido, o filtra el ping, o su '
               . 'prefijo no se esta anunciando.';
    } else {
        $verSt = 'good';
        $verTx = 'Alcanzable desde todas las regiones';
        $min = $latencias ? round(min($latencias), 1) : 0;
        $max = $latencias ? round(max($latencias), 1) : 0;
        $expl  = "Latencia de {$min} a {$max} ms segun la distancia. El enrutado llega bien a todo el mundo.";
    }

    $out = "Latencia global hasta {$name}\n" . str_repeat('-', 52) . "\n";
    $out .= $verTx . "\n\n";
    foreach ($rows as $r) {
        $out .= sprintf("  %-22s %-26s %s\n", $r['k'], $r['v'], $r['note']);
    }
    $out .= "\nSondas: globalping.io (red comunitaria de jsDelivr). Cada linea es una\n"
          . "sonda real en esa region. Un fallo aislado por region delata enrutado,\n"
          . "no una caida del servidor.\n";

    return lg_ok(trim($out), [
        lg_block('rows', 'Veredicto: ' . $verTx, [lg_row('Diagnostico', $expl, $verSt)], $verSt),
        lg_block('rows', 'Latencia por region (sonda real)', $rows),
    ], ['target' => $name]);
}
