<?php
/**
 * Centinela - analisis de ataques a partir de los logs de autenticacion.
 *
 * Lectura incremental: se guarda inodo + offset entre ejecuciones, de forma
 * que cada pasada solo procesa lo nuevo. Si el fichero rota (cambia el inodo
 * o encoge) se vuelve a empezar desde el principio.
 */

declare(strict_types=1);

/** Rutas candidatas del log de autenticacion segun la distribucion. */
function auth_log_path(): ?string
{
    foreach (['/var/log/auth.log', '/var/log/secure'] as $p) {
        if (is_readable($p)) {
            return $p;
        }
    }
    return null;
}

/** Numero de dias de historico que conservamos. */
const CENT_HISTORY_DAYS = 14;

/** Intentos en 7 dias a partir de los cuales una IP sin bloquear es un aviso. */
const CENT_LOOSE_MIN = 300;

/** Y a partir de los cuales pasa a critico. */
const CENT_LOOSE_CRIT = 1000;

/** Nombres de usuario distintos desde una IP para llamarlo enumeracion. */
const CENT_ENUM_MIN = 15;

/** Intentos desde un mismo prefijo para plantearse bloquearlo entero. */
const CENT_PREFIX_MIN = 400;

/** O esta proporcion del total de la ventana. */
const CENT_PREFIX_SHARE = 0.25;

/** IPs distintas en un dia para hablar de campana distribuida. */
const CENT_DIST_MIN = 30;

/** Jail donde caen los bloqueos hechos a mano desde el panel. */
const CENT_BAN_JAIL = 'plesk-permanent-ban';

/**
 * Procesa el log de autenticacion y actualiza el almacen de eventos.
 * Devuelve el analisis agregado listo para el panel.
 */
function collect_attacks(): array
{
    $store = load_event_store();
    $path  = auth_log_path();

    if ($path === null) {
        // Sin fichero: intentamos journald como fuente alternativa
        $lines = explode("\n", sh("journalctl -u sshd -u ssh --since '-1h' --no-pager -q 2>/dev/null", 30));
        foreach ($lines as $line) {
            ingest_auth_line($store, $line);
        }
    } else {
        $st    = @stat($path);
        $inode = $st ? (int) $st['ino'] : 0;
        $size  = $st ? (int) $st['size'] : 0;
        $prev  = $store['reader'] ?? ['inode' => 0, 'offset' => 0];

        $offset = ($prev['inode'] === $inode && $prev['offset'] <= $size) ? (int) $prev['offset'] : 0;

        // Primera pasada sobre un log grande: limitamos a los ultimos 20 MB
        if ($offset === 0 && $size > 20971520) {
            $offset = $size - 20971520;
        }

        $fh = @fopen($path, 'rb');
        if ($fh) {
            fseek($fh, $offset);
            $count = 0;
            while (($line = fgets($fh)) !== false && $count < 400000) {
                ingest_auth_line($store, rtrim($line, "\r\n"));
                $count++;
            }
            $store['reader'] = ['inode' => $inode, 'offset' => ftell($fh)];
            fclose($fh);
        }

        // Si acabamos de empezar y el log rotado existe, lo incorporamos una vez
        if ($prev['inode'] === 0) {
            foreach (glob($path . '.1') ?: [] as $rot) {
                foreach (explode("\n", (string) slurp($rot, 10485760)) as $line) {
                    ingest_auth_line($store, $line);
                }
            }
        }
    }

    prune_event_store($store);
    enrich_asn($store);
    save_event_store($store);

    return build_attack_report($store);
}

/** Almacen persistente de eventos agregados. */
function load_event_store(): array
{
    $f   = state_dir() . '/events.json';
    $raw = is_file($f) ? slurp($f, 20971520) : null;
    $d   = $raw !== null ? json_decode($raw, true) : null;
    if ($raw !== null && !is_array($d)) {
        // slurp() corta la lectura al llegar al tope, asi que un fichero que
        // haya crecido de mas llega truncado y no decodifica. Reiniciar el
        // historico en silencio seria perder justo lo que esta herramienta
        // existe para conservar: al menos queda constancia en el journal.
        clog('events.json ilegible o truncado (' . strlen($raw) . ' bytes); se reinicia el historico de ataques');
    }
    if (!is_array($d)) {
        $d = [];
    }
    return $d + [
        'since'     => time(),   // desde cuando hay historico: sin esto, el
                                 // primer dia todo pareceria «nunca visto»
        'reader'    => ['inode' => 0, 'offset' => 0],
        'days'      => [],   // YYYY-MM-DD => ['ips'=>[ip=>n], 'users'=>[u=>n], 'hours'=>[H=>n], 'total'=>n]
        'successes' => [],   // logins correctos recientes
        'asn'       => [],   // ip => datos de red, cacheado
        'services'  => [],   // servicio => contador por dia
        'first_seen' => [],  // ip => timestamp
        'last_seen'  => [],  // ip => timestamp
        'known_ok'   => [],  // ip => primera vez que entro bien
        'ip_users'   => [],  // ip => [usuario => intentos]
        'ip_svc'     => [],  // ip => [servicio => intentos], para la geo-valla
    ];
}

function save_event_store(array $store): void
{
    write_atomic(
        state_dir() . '/events.json',
        json_encode($store, JSON_UNESCAPED_SLASHES),
        0640
    );
}

/** Convierte la marca de tiempo del syslog a epoch. */
function syslog_ts(string $line): ?int
{
    // Formato RFC3164: "Aug 10 09:57:46"
    if (preg_match('/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/', $line, $m)) {
        $year = (int) date('Y');
        $ts = strtotime("{$m[1]} {$m[2]} {$year} {$m[3]}:{$m[4]}:{$m[5]}");
        // Si sale en el futuro, es del ano pasado (cambio de ano en el log)
        if ($ts !== false && $ts > time() + 86400) {
            $ts = strtotime("{$m[1]} {$m[2]} " . ($year - 1) . " {$m[3]}:{$m[4]}:{$m[5]}");
        }
        return $ts ?: null;
    }
    // Formato RFC5424 / journald: "2026-08-10T09:57:46"
    if (preg_match('/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/', $line, $m)) {
        $ts = strtotime($m[1]);
        return $ts ?: null;
    }
    return null;
}

/**
 * Servicio al que iba el intento, a partir del programa que escribio la linea.
 *
 * Se mira el campo de programa del syslog («sshd[123]:»), no la linea entera:
 * el nombre del propio servidor aparece en todas las lineas, asi que buscar
 * «plesk» en el texto clasificaba como panel hasta los intentos contra SSH en
 * cualquier maquina que se llame plesk.algo.
 */
function line_service(string $line): string
{
    // RFC3164: «Aug 18 16:50:43 host sshd[245588]: ...»
    // journald/RFC5424: «2026-08-18T16:50:43+00:00 host sshd[245588]: ...»
    $prog = '';
    if (preg_match('/^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]{8}|\S*\d{2}:\d{2}:\d{2}\S*)\s+\S+\s+([a-zA-Z0-9._\/-]+)(?:\[\d+\])?:/', $line, $m)) {
        $prog = strtolower($m[1]);
    }

    foreach ([
        'sshd'          => 'ssh',
        'dovecot'       => 'imap/pop3',
        'postfix'       => 'smtp',
        'sasl'          => 'smtp',
        'smtp'          => 'smtp',
        'proftpd'       => 'ftp',
        'vsftpd'        => 'ftp',
        'pure-ftpd'     => 'ftp',
        'sw-cp-server'  => 'panel',
        'plesk'         => 'panel',
        'psa'           => 'panel',
    ] as $aguja => $servicio) {
        if ($prog !== '' && str_contains($prog, $aguja)) {
            return $servicio;
        }
    }

    // Sin campo de programa reconocible (journalctl -o cat, formatos raros),
    // se cae al texto, pero sin buscar «plesk»: es el nombre de demasiados
    // servidores como para deducir nada de el.
    if (str_contains($line, 'dovecot')) {
        return 'imap/pop3';
    }
    if (str_contains($line, 'postfix') || str_contains($line, 'sasl')) {
        return 'smtp';
    }
    if (str_contains($line, 'proftpd') || str_contains($line, 'vsftpd')) {
        return 'ftp';
    }
    if (str_contains($line, 'sw-cp-server')) {
        return 'panel';
    }
    return 'ssh';
}

/** Incorpora una linea del log al almacen. */
function ingest_auth_line(array &$store, string $line): void
{
    if ($line === '') {
        return;
    }

    $isFail = str_contains($line, 'Failed password')
        || str_contains($line, 'Invalid user')
        || str_contains($line, 'authentication failure')
        || str_contains($line, 'Failed publickey');
    $isOk   = str_contains($line, 'Accepted ');

    if (!$isFail && !$isOk) {
        return;
    }

    if (!preg_match('/(?:from|rhost=)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]{6,})/', $line, $m)) {
        return;
    }
    $ip = $m[1];
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return;
    }

    $ts  = syslog_ts($line) ?? time();
    $day = date('Y-m-d', $ts);
    $hr  = (int) date('G', $ts);

    // Usuario objetivo
    $user = null;
    if (preg_match('/Invalid user (\S+)/', $line, $um)) {
        $user = $um[1];
    } elseif (preg_match('/for (?:invalid user )?(\S+) from/', $line, $um)) {
        $user = $um[1];
    } elseif (preg_match('/user=(\S+)/', $line, $um)) {
        $user = $um[1];
    }
    if ($user !== null) {
        $user = substr(preg_replace('/[^\w.@-]/', '', $user), 0, 40);
        if ($user === '') {
            $user = null;
        }
    }

    $svc = line_service($line);

    if ($isOk) {
        $method = str_contains($line, 'publickey') ? 'clave publica' : 'contrasena';
        // Se marca aqui, antes de apuntarla como conocida: en el informe ya no
        // habria forma de distinguir la primera vez de las siguientes.
        $nueva = !isset($store['known_ok'][$ip]);
        if ($nueva) {
            $store['known_ok'][$ip] = $ts;
        }
        $store['successes'][] = ['ts' => $ts, 'ip' => $ip, 'user' => $user ?? '?', 'method' => $method,
                                 'service' => $svc, 'new_ip' => $nueva];
        if (count($store['successes']) > 500) {
            $store['successes'] = array_slice($store['successes'], -500);
        }
        return;
    }

    $d = &$store['days'][$day];
    if (!is_array($d)) {
        $d = ['ips' => [], 'users' => [], 'hours' => [], 'services' => [], 'total' => 0];
    }
    $d['total']++;
    $d['ips'][$ip]  = ($d['ips'][$ip] ?? 0) + 1;
    $d['hours'][$hr] = ($d['hours'][$hr] ?? 0) + 1;
    $d['services'][$svc] = ($d['services'][$svc] ?? 0) + 1;
    if ($user !== null) {
        $d['users'][$user] = ($d['users'][$user] ?? 0) + 1;
    }
    unset($d);

    // Contra que servicio va cada IP: la geo-valla solo actua sobre los
    // servicios de administracion, y este es el unico sitio donde se sabe.
    $store['ip_svc'][$ip][$svc] = ($store['ip_svc'][$ip][$svc] ?? 0) + 1;

    // Que usuarios prueba cada IP: probar muchos nombres distintos es
    // enumeracion, un patron distinto al de insistir con uno solo.
    if ($user !== null && count($store['ip_users'][$ip] ?? []) < 60) {
        $store['ip_users'][$ip][$user] = ($store['ip_users'][$ip][$user] ?? 0) + 1;
    }

    if (!isset($store['first_seen'][$ip])) {
        $store['first_seen'][$ip] = $ts;
    }
    $store['last_seen'][$ip] = max($ts, $store['last_seen'][$ip] ?? 0);
}

/** Descarta datos mas antiguos que la ventana de historico. */
function prune_event_store(array &$store): void
{
    $cutoff = date('Y-m-d', time() - CENT_HISTORY_DAYS * 86400);
    foreach (array_keys($store['days']) as $day) {
        if ($day < $cutoff) {
            unset($store['days'][$day]);
        }
    }
    ksort($store['days']);

    // Limitamos el numero de IPs por dia para que el fichero no crezca sin fin
    foreach ($store['days'] as $day => &$d) {
        if (count($d['ips']) > 3000) {
            arsort($d['ips']);
            $d['ips'] = array_slice($d['ips'], 0, 3000, true);
        }
        if (count($d['users']) > 500) {
            arsort($d['users']);
            $d['users'] = array_slice($d['users'], 0, 500, true);
        }
    }
    unset($d);

    $tsCut = time() - CENT_HISTORY_DAYS * 86400;
    foreach (['first_seen', 'last_seen'] as $k) {
        $store[$k] = array_filter($store[$k], fn($t) => $t >= $tsCut);
        // Podar solo por antiguedad no acota nada: estos mapas llevan una
        // clave por IP de origen y desde un /64 de IPv6 se generan sin limite.
        // Nos quedamos con las mas recientes, igual que se hace por dia.
        if (count($store[$k]) > 20000) {
            arsort($store[$k]);
            $store[$k] = array_slice($store[$k], 0, 20000, true);
        }
    }
    $store['successes'] = array_values(array_filter($store['successes'], fn($s) => $s['ts'] >= $tsCut));

    // ip_users e ip_svc solo interesan mientras la IP siga en la ventana
    $store['ip_users'] = array_intersect_key($store['ip_users'], $store['last_seen']);
    $store['ip_svc']   = array_intersect_key($store['ip_svc'], $store['last_seen']);
    if (count($store['ip_users']) > 5000) {
        $store['ip_users'] = array_slice($store['ip_users'], 0, 5000, true);
    }
    // known_ok es memoria a largo plazo (de eso vive «IP nunca vista») pero no
    // puede crecer sin fin: se conservan las 2000 mas recientes.
    if (count($store['known_ok']) > 2000) {
        arsort($store['known_ok']);
        $store['known_ok'] = array_slice($store['known_ok'], 0, 2000, true);
    }

    // La cache de ASN se mantiene 30 dias
    $store['asn'] = array_filter($store['asn'], fn($a) => ($a['at'] ?? 0) > time() - 2592000);
}

/**
 * Resuelve ASN, prefijo y pais via el servicio DNS de Team Cymru.
 * No requiere clave de API ni salida HTTP; solo consultas DNS.
 * Limitado a un numero de IPs por pasada para no alargar la ejecucion.
 */
function enrich_asn(array &$store): void
{
    if (!have('dig')) {
        return;
    }

    // IPs relevantes: las mas activas de los ultimos 3 dias, sin datos aun
    $recent = [];
    $from = date('Y-m-d', time() - 3 * 86400);
    foreach ($store['days'] as $day => $d) {
        if ($day < $from) {
            continue;
        }
        foreach ($d['ips'] as $ip => $n) {
            $recent[$ip] = ($recent[$ip] ?? 0) + $n;
        }
    }
    arsort($recent);

    // La geo-valla decide por pais, asi que las IPs que tocan los servicios
    // vigilados van primero y con mas presupuesto: una IP sin pais resuelto
    // es una IP sobre la que la valla no puede pronunciarse todavia.
    $prioridad = [];
    if (function_exists('guard_policy') && !empty(guard_policy()['enabled'])) {
        // Lo primero de todo: las IPs con acceso CORRECTO reciente. Sin pais
        // resuelto, la alerta de acceso fuera de politica no puede saltar, y
        // un robo de credencial limpio no deja fallos que las prioricen.
        $corte = time() - 2 * 86400;
        foreach ($store['successes'] ?? [] as $sx) {
            $sip = (string) ($sx['ip'] ?? '');
            if (($sx['ts'] ?? 0) >= $corte && $sip !== '' && !isset($store['asn'][$sip])
                && filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
                && !in_array($sip, $prioridad, true)) {
                $prioridad[] = $sip;
            }
        }
        $vigilados = guard_policy()['services'] ?? [];
        foreach (array_keys($recent) as $ip) {
            if (isset($store['asn'][$ip])) {
                continue;
            }
            foreach ($vigilados as $svc) {
                if (!empty($store['ip_svc'][$ip][$svc])) {
                    $prioridad[] = $ip;
                    break;
                }
            }
        }
    }

    $todo = array_slice($prioridad, 0, 25);
    foreach (array_slice(array_keys($recent), 0, 400) as $ip) {
        if (count($todo) >= 30) {   // presupuesto por pasada
            break;
        }
        if (!isset($store['asn'][$ip]) && !in_array($ip, $todo, true)) {
            $todo[] = $ip;
        }
    }

    foreach ($todo as $ip) {
        $store['asn'][$ip] = asn_lookup($ip) + ['at' => time()];
    }
}

/** Consulta Team Cymru para una IP concreta. */
function asn_lookup(string $ip): array
{
    $empty = ['asn' => null, 'prefix' => null, 'cc' => null, 'org' => null];

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $q = implode('.', array_reverse(explode('.', $ip))) . '.origin.asn.cymru.com';
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $hex = bin2hex((string) inet_pton($ip));
        $q = implode('.', array_reverse(str_split($hex))) . '.origin6.asn.cymru.com';
    } else {
        return $empty;
    }

    $txt = trim(run(['/usr/bin/dig', '+short', '+time=3', '+tries=1', $q, 'TXT'], 8)['out']);
    if ($txt === '') {
        return $empty;
    }
    // Puede devolver varias lineas si el prefijo tiene varios origenes
    $first = trim(explode("\n", $txt)[0], "\" \t");
    $parts = array_map('trim', explode('|', $first));
    if (count($parts) < 3) {
        return $empty;
    }
    $asn = trim(explode(' ', $parts[0])[0]);

    $org = null;
    if ($asn !== '' && ctype_digit($asn)) {
        $atxt = trim(run(['/usr/bin/dig', '+short', '+time=3', '+tries=1', "AS{$asn}.asn.cymru.com", 'TXT'], 8)['out']);
        $ap = explode('|', trim($atxt, "\" \t"));
        $org = isset($ap[4]) ? trim($ap[4]) : null;
    }

    return [
        'asn'    => $asn !== '' ? (int) $asn : null,
        'prefix' => $parts[1] ?? null,
        'cc'     => $parts[2] ?? null,
        'org'    => $org,
    ];
}

/**
 * Cruza los atacantes detectados con lo que fail2ban tiene bloqueado.
 *
 * Se hace fuera de los modulos porque necesita el resultado de dos: el
 * analisis del log dice quien ataca y fail2ban dice a quien retiene. La
 * pregunta que importa —«esto lo esta parando algo»— solo se responde
 * juntando las dos mitades.
 */
function cross_reference_bans(array &$report, array &$all): void
{
    $f2b = $report['fail2ban'] ?? [];
    if (empty($f2b['installed']) || empty($f2b['active'])) {
        return;   // ya hay un hallazgo propio para eso
    }

    $banned = $f2b['banned_map'] ?? [];

    // Las IPs que solo atacan por web viven en otro modulo, pero la pregunta
    // y el boton del panel son los mismos.
    foreach (($report['web']['top_ips'] ?? []) as $i => $ip) {
        $report['web']['top_ips'][$i]['banned_in'] = $banned[$ip['ip']] ?? [];
    }

    $tops = $report['attacks']['top_ips'] ?? [];
    if (!$tops) {
        return;
    }

    $sueltas = [];
    foreach ($tops as $i => $ip) {
        $jails = $banned[$ip['ip']] ?? [];
        $report['attacks']['top_ips'][$i]['banned_in'] = $jails;
        if (!$jails && (int) $ip['count'] >= CENT_LOOSE_MIN) {
            $sueltas[] = $report['attacks']['top_ips'][$i];
        }
    }
    $report['attacks']['loose'] = count($sueltas);

    if (!$sueltas) {
        return;
    }

    $peor = max(array_map(fn($x) => (int) $x['count'], $sueltas));
    $lista = array_slice($sueltas, 0, 5);
    $detalle = implode(', ', array_map(
        fn($x) => $x['ip'] . ' (' . number_format((int) $x['count'], 0, ',', '.') . ' intentos'
                . (!empty($x['cc']) ? ', ' . $x['cc'] : '') . ')',
        $lista
    ));
    if (count($sueltas) > count($lista)) {
        $detalle .= ' y ' . (count($sueltas) - count($lista)) . ' mas';
    }

    $f = finding(
        'atk.unblocked',
        $peor >= CENT_LOOSE_CRIT ? SEV_CRIT : SEV_WARN,
        count($sueltas) . ' atacante(s) con volumen y sin bloquear',
        $detalle . '. Siguen llegando a los servicios: ningun jail de fail2ban los retiene.',
        'Bloquearlas desde el panel, y revisar por que el jail no las coge',
        guide(
            'Que fail2ban este corriendo no significa que este cogiendo a todo el mundo. Un atacante que '
            . 'reparte los intentos entre varios servicios, o que va despacio, se queda por debajo del umbral '
            . 'de cada jail y sigue probando indefinidamente sin que nadie lo pare.',
            [
                ['do' => 'Bloquealas ya desde la tabla de IPs de origen de este panel, con el boton Bloquear. '
                       . 'Tambien puedes hacerlo a mano',
                 'cmd' => 'fail2ban-client set ' . CENT_BAN_JAIL . ' banip ' . ($lista[0]['ip'] ?? 'IP')],
                ['do' => 'Mira contra que servicio estan yendo, para saber que jail deberia haberlas cogido',
                 'cmd' => 'grep -h ' . escapeshellarg((string) ($lista[0]['ip'] ?? '')) . ' /var/log/auth.log /var/log/maillog /var/log/mail.log 2>/dev/null | tail -20'],
                ['do' => 'Comprueba que ese jail existe y esta leyendo el registro correcto',
                 'cmd' => 'fail2ban-client status'],
                ['do' => 'Si el jail existe pero no salta, suele ser el umbral: baja maxretry o alarga findtime '
                       . 'en Herramientas y configuracion > Proteccion contra ataques de fuerza bruta.'],
                ['do' => 'Si el mismo operador aparece una y otra vez con IPs distintas, bloquea el prefijo entero '
                       . 'en vez de ir una a una',
                 'cmd' => 'fail2ban-client set ' . CENT_BAN_JAIL . ' banip ' . ($lista[0]['prefix'] ?? 'PREFIJO')],
            ],
            'fail2ban-client banned ' . ($lista[0]['ip'] ?? 'IP'),
            'Antes de bloquear un prefijo entero comprueba que no hay nada tuyo dentro: un rango de tu propio '
            . 'proveedor puede incluir la IP desde la que administras.'
        )
    );

    $all[] = $f;
    $report['attacks']['findings'][] = $f;
}

/** Construye el informe agregado que consume el panel. */
function build_attack_report(array $store): array
{
    $today     = date('Y-m-d');
    $yesterday = date('Y-m-d', time() - 86400);
    $days      = $store['days'];

    // Serie diaria
    $series = [];
    for ($i = CENT_HISTORY_DAYS - 1; $i >= 0; $i--) {
        $d = date('Y-m-d', time() - $i * 86400);
        $series[] = ['date' => $d, 'count' => $days[$d]['total'] ?? 0];
    }

    // Serie horaria de las ultimas 48 horas
    $hourly = [];
    for ($i = 47; $i >= 0; $i--) {
        $t  = time() - $i * 3600;
        $d  = date('Y-m-d', $t);
        $h  = (int) date('G', $t);
        $hourly[] = ['t' => date('Y-m-d H:00', $t), 'count' => $days[$d]['hours'][$h] ?? 0];
    }

    // Agregados de los ultimos 7 dias
    $ips = $users = $services = [];
    $from = date('Y-m-d', time() - 7 * 86400);
    $total7 = 0;
    foreach ($days as $day => $d) {
        if ($day < $from) {
            continue;
        }
        $total7 += $d['total'];
        foreach ($d['ips'] as $ip => $n)   { $ips[$ip]   = ($ips[$ip] ?? 0) + $n; }
        foreach ($d['users'] as $u => $n)  { $users[$u]  = ($users[$u] ?? 0) + $n; }
        foreach (($d['services'] ?? []) as $s => $n) { $services[$s] = ($services[$s] ?? 0) + $n; }
    }
    arsort($ips);
    arsort($users);
    arsort($services);

    // Top de IPs con datos de red
    $topIps = [];
    foreach (array_slice($ips, 0, 50, true) as $ip => $n) {
        $a = $store['asn'][$ip] ?? [];
        $topIps[] = [
            'ip'        => $ip,
            'count'     => $n,
            'asn'       => $a['asn'] ?? null,
            'org'       => $a['org'] ?? null,
            'cc'        => $a['cc'] ?? null,
            'prefix'    => $a['prefix'] ?? null,
            'first_seen' => $store['first_seen'][$ip] ?? null,
            'last_seen' => $store['last_seen'][$ip] ?? null,
        ];
    }

    // Ranking por pais y por operador
    $byCc = $byAsn = [];
    foreach ($ips as $ip => $n) {
        $a = $store['asn'][$ip] ?? [];
        if (!empty($a['cc'])) {
            $byCc[$a['cc']] = ($byCc[$a['cc']] ?? 0) + $n;
        }
        if (!empty($a['asn'])) {
            $key = 'AS' . $a['asn'] . '|' . ($a['org'] ?? '');
            $byAsn[$key] = ($byAsn[$key] ?? 0) + $n;
        }
    }
    arsort($byCc);
    arsort($byAsn);

    $asnList = [];
    foreach (array_slice($byAsn, 0, 15, true) as $key => $n) {
        [$as, $org] = array_pad(explode('|', $key, 2), 2, '');
        $asnList[] = ['asn' => $as, 'org' => $org, 'count' => $n];
    }

    // Logins correctos recientes
    $succ = array_slice(array_reverse($store['successes']), 0, 40);

    // Hallazgos derivados del analisis
    $findings = [];
    $todayTotal = $days[$today]['total'] ?? 0;
    $avg = 0;
    $n = 0;
    foreach ($series as $s) {
        if ($s['date'] !== $today) {
            $avg += $s['count'];
            $n++;
        }
    }
    $avg = $n > 0 ? $avg / $n : 0;

    if ($avg > 50 && $todayTotal > $avg * 3) {
        $findings[] = finding('atk.spike', SEV_WARN, 'Pico de intentos de acceso',
            sprintf('%d hoy frente a una media de %.0f/dia', $todayTotal, $avg),
            'Revisar el origen y considerar bloqueo por rango',
            guide(
                'Un pico asi suele ser una campana dirigida a este servidor, no el ruido de fondo habitual. '
                . 'Mientras dura conviene comprobar que las defensas estan aguantando y que nadie ha acertado.',
                [
                    ['do' => 'Mira de donde viene el grueso de los intentos, en la seccion de ataques del panel o '
                           . 'directamente del registro',
                     'cmd' => 'journalctl -u ssh --since today | grep -i "failed password" | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn | head'],
                    ['do' => 'Comprueba que fail2ban los esta bloqueando de verdad',
                     'cmd' => 'fail2ban-client status ssh'],
                    ['do' => 'Si todo sale del mismo rango, bloquealo entero en el cortafuegos de Plesk, o de forma '
                           . 'inmediata con fail2ban',
                     'cmd' => 'fail2ban-client set sshd banip RANGO'],
                    ['do' => 'Endurece temporalmente el jail: mas tiempo de bloqueo y menos intentos permitidos, '
                           . 'desde Herramientas y configuracion > Proteccion contra ataques de fuerza bruta.'],
                    ['do' => 'Confirma que ninguno de esos origenes ha llegado a entrar',
                     'cmd' => 'last -F | head -20; grep -i "accepted" /var/log/auth.log | tail -20'],
                ],
                'journalctl -u ssh --since today | grep -ci "failed password"'
            ));
    }

    // Logins correctos por contrasena desde IPs que tambien han fallado mucho
    foreach ($succ as $s) {
        if (($ips[$s['ip']] ?? 0) > 20 && $s['method'] === 'contrasena') {
            $findings[] = finding('atk.success_suspect', SEV_CRIT,
                'Login correcto desde una IP con muchos fallos previos',
                "{$s['ip']} accedio como {$s['user']} el " . date('d/m/Y H:i', $s['ts']),
                'Verificar si es legitimo; si no, rotar credenciales y revisar el servidor',
                guide(
                    'Una direccion que falla decenas de veces y despues acierta es el patron exacto de una fuerza '
                    . 'bruta que ha tenido exito. Si no reconoces ese acceso, tratalo como una intrusion en curso.',
                    [
                        ['do' => '¿Reconoces la direccion? Si eres tu tecleando mal la contrasena desde una IP fija, '
                               . 'anotala y no hay mas que hacer',
                         'cmd' => 'whois ' . escapeshellarg($s['ip']) . ' | grep -iE "netname|orgname|country|descr" | head'],
                        ['do' => 'Mira si la sesion sigue abierta y que esta ejecutando',
                         'cmd' => 'who; ps -ef --forest | head -40'],
                        ['do' => 'Revisa lo que suele dejar un intruso: claves autorizadas nuevas y tareas programadas',
                         'cmd' => 'cat /root/.ssh/authorized_keys 2>/dev/null; crontab -l -u root; ls -la /etc/cron.d/'],
                        ['do' => 'Si no es legitimo, corta el acceso ya: expulsa la sesion, bloquea la IP y cambia '
                               . 'la contrasena de la cuenta',
                         'cmd' => 'fail2ban-client set sshd banip ' . escapeshellarg($s['ip']) . '; passwd ' . escapeshellarg($s['user'])],
                        ['do' => 'Despues, desactiva la autenticacion por contrasena en SSH para que no se repita.'],
                    ],
                    'last -F | head -20',
                    'Si confirmas la intrusion, cambiar la contrasena no basta: pueden haber dejado una clave o una '
                    . 'tarea programada. Revisa antes de dar el incidente por cerrado, y conserva los registros.'
                ));
            break;
        }
    }

    // --- Acceso correcto desde una direccion nunca vista ------------------
    // Solo tiene sentido cuando hay historico suficiente: recien instalado,
    // todas las direcciones son «nuevas» y el aviso no diria nada.
    if ((time() - (int) ($store['since'] ?? time())) > 86400) {
        $nuevos = array_values(array_filter(
            $succ,
            fn($x) => !empty($x['new_ip']) && $x['ts'] >= time() - 86400
        ));
        if ($nuevos) {
            $lista = array_slice($nuevos, 0, 4);
            $detalle = implode('; ', array_map(function ($x) use ($store) {
                $a = $store['asn'][$x['ip']] ?? [];
                return $x['user'] . '@' . $x['ip']
                    . (!empty($a['cc']) ? ' (' . $a['cc'] . (!empty($a['org']) ? ', ' . $a['org'] : '') . ')' : '')
                    . ' el ' . date('d/m H:i', $x['ts'])
                    . ' por ' . $x['method'] . ' en ' . $x['service'];
            }, $lista));

            $findings[] = finding(
                'atk.newlogin',
                SEV_WARN,
                count($nuevos) . ' acceso(s) correcto(s) desde direcciones nunca vistas',
                $detalle . '. Ninguna de ellas habia entrado antes en la ventana de historico.',
                'Confirmar que eres tu o alguien de confianza; si no, rotar credenciales de inmediato',
                guide(
                    'Un acceso correcto no dispara ninguna alarma por si mismo, y es justo lo que busca quien ha '
                    . 'conseguido una credencial: entrar sin ruido. Lo unico que distingue el acceso legitimo del '
                    . 'robado es si reconoces el sitio desde el que se hizo.',
                    [
                        ['do' => '¿Reconoces la direccion y la hora? Si es tu oficina, tu casa o tu VPN, no hay mas.'],
                        ['do' => 'Si no la reconoces, mira que ha hecho esa sesion',
                         'cmd' => 'last -F | head -20; journalctl _COMM=sshd --since "-24 hours" | grep -i "' . ($lista[0]['ip'] ?? '') . '"'],
                        ['do' => 'Revisa lo que suele quedar detras: claves autorizadas y tareas programadas',
                         'cmd' => 'cat /root/.ssh/authorized_keys 2>/dev/null; crontab -l -u root; ls -la /etc/cron.d/'],
                        ['do' => 'Si no es legitimo, cambia la contrasena de esa cuenta y corta la sesion',
                         'cmd' => 'passwd ' . escapeshellarg((string) ($lista[0]['user'] ?? 'USUARIO'))
                                . '; pkill -KILL -u ' . escapeshellarg((string) ($lista[0]['user'] ?? 'USUARIO'))],
                    ],
                    'last -F | head -10',
                    'No borres registros mientras investigas: son lo unico que dice por donde entraron.'
                )
            );
        }
    }

    // --- Enumeracion de usuarios -----------------------------------------
    $enum = [];
    foreach ($store['ip_users'] ?? [] as $ip => $us) {
        if (is_array($us) && count($us) >= CENT_ENUM_MIN && ($ips[$ip] ?? 0) > 0) {
            $enum[$ip] = $us;
        }
    }
    if ($enum) {
        arsort($enum);
        $primera = (string) array_key_first($enum);
        $muestra = array_slice(array_keys($enum[$primera]), 0, 8);
        $findings[] = finding(
            'atk.userenum',
            SEV_WARN,
            count($enum) . ' IP(s) probando nombres de usuario a ciegas',
            $primera . ' ha probado ' . count($enum[$primera]) . ' nombres distintos ('
                . implode(', ', $muestra) . '…). Es enumeracion: buscan que cuenta existe antes de insistir.',
            'Bloquearlas y asegurarse de que SSH no acepta contrasenas',
            guide(
                'Probar muchos nombres distintos es la fase previa de un ataque dirigido: primero averiguan que '
                . 'cuentas existen y despues concentran los intentos en las que responden distinto. Que aparezcan '
                . 'nombres de personas reales o de aplicaciones alojadas aqui es mala senal.',
                [
                    ['do' => 'Mira la lista completa que ha probado esa IP, por si hay nombres que solo se pueden '
                           . 'conocer desde dentro',
                     'cmd' => 'grep ' . escapeshellarg($primera) . ' /var/log/auth.log | grep -oE "(Invalid user|for) [^ ]+" | sort | uniq -c | sort -rn | head -20'],
                    ['do' => 'Bloqueala desde la tabla de origenes de este panel, o a mano',
                     'cmd' => 'fail2ban-client set ' . CENT_BAN_JAIL . ' banip ' . $primera],
                    ['do' => 'Comprueba que ninguna de esas cuentas existe de verdad y puede entrar',
                     'cmd' => 'getent passwd | awk -F: "\$3 >= 1000 {print \$1, \$7}"'],
                    ['do' => 'Con claves en vez de contrasenas, la enumeracion deja de importar: aunque acierten '
                           . 'el nombre, no hay contrasena que adivinar.'],
                ],
                'grep -c ' . escapeshellarg($primera) . ' /var/log/auth.log'
            )
        );
    }

    // --- Concentracion en un mismo prefijo --------------------------------
    $porPrefijo = [];
    foreach ($ips as $ip => $n) {
        $pfx = $store['asn'][$ip]['prefix'] ?? null;
        if (!$pfx) {
            continue;
        }
        $porPrefijo[$pfx]['count'] = ($porPrefijo[$pfx]['count'] ?? 0) + $n;
        $porPrefijo[$pfx]['ips'][$ip] = true;
        $porPrefijo[$pfx]['org'] = $store['asn'][$ip]['org'] ?? '';
        $porPrefijo[$pfx]['cc']  = $store['asn'][$ip]['cc'] ?? '';
    }
    uasort($porPrefijo, fn($a, $b) => $b['count'] <=> $a['count']);
    $pfx = array_key_first($porPrefijo);
    if ($pfx !== null) {
        $d = $porPrefijo[$pfx];
        $nIps = count($d['ips']);
        $cuota = $total7 > 0 ? $d['count'] / $total7 : 0;
        if ($nIps >= 3 && ($d['count'] >= CENT_PREFIX_MIN || $cuota >= CENT_PREFIX_SHARE)) {
            $findings[] = finding(
                'atk.prefix',
                SEV_WARN,
                'Un mismo rango concentra ' . number_format($d['count'], 0, ',', '.') . ' intentos',
                $pfx . ' (' . ($d['org'] ?: 'operador desconocido') . ($d['cc'] ? ', ' . $d['cc'] : '') . '): '
                    . number_format($d['count'], 0, ',', '.') . ' intentos desde ' . $nIps . ' direcciones distintas, '
                    . 'el ' . round($cuota * 100) . '% de todo lo que llega.',
                'Bloquear el prefijo entero en vez de ir IP por IP',
                guide(
                    'Cuando el mismo rango vuelve una y otra vez con direcciones distintas, bloquear de una en una '
                    . 'es perder el tiempo: tienen mas. El bloqueo por prefijo corta la fuente.',
                    [
                        ['do' => 'Comprueba a quien pertenece el rango antes de tocarlo',
                         'cmd' => 'whois ' . escapeshellarg((string) $pfx) . ' | grep -iE "netname|orgname|country|abuse" | head'],
                        ['do' => 'Asegurate de que no hay nada tuyo dentro: clientes, oficinas, tu propia VPN.'],
                        ['do' => 'Bloquea el prefijo completo',
                         'cmd' => 'fail2ban-client set ' . CENT_BAN_JAIL . ' banip ' . $pfx],
                        ['do' => 'Si el operador reincide con varios prefijos, planteate bloquear su ASN en el '
                               . 'cortafuegos de Plesk en vez de rango a rango.'],
                    ],
                    'fail2ban-client banned | grep -c ' . escapeshellarg(explode('/', (string) $pfx)[0]),
                    'Un prefijo puede tener cientos de direcciones legitimas detras. Si el rango es de un operador '
                    . 'de acceso domestico o movil, bloquearlo entero deja fuera a usuarios reales.'
                )
            );
        }
    }

    // --- Campana distribuida ---------------------------------------------
    $ipsHoy = count($days[$today]['ips'] ?? []);
    $mediaIps = 0;
    $dias = 0;
    foreach ($days as $day => $d) {
        if ($day !== $today) {
            $mediaIps += count($d['ips'] ?? []);
            $dias++;
        }
    }
    $mediaIps = $dias > 0 ? $mediaIps / $dias : 0;
    if ($ipsHoy >= CENT_DIST_MIN && $mediaIps > 0 && $ipsHoy > $mediaIps * 3) {
        $findings[] = finding(
            'atk.distributed',
            SEV_WARN,
            'Campana distribuida en marcha',
            sprintf('%d direcciones distintas hoy frente a una media de %.0f al dia. Pocos intentos por IP: '
                . 'reparten la carga para no llegar al umbral de ningun jail.', $ipsHoy, $mediaIps),
            'Endurecer temporalmente los umbrales y vigilar los accesos correctos',
            guide(
                'Repartir el ataque entre cientos de direcciones es la forma estandar de esquivar a fail2ban: '
                . 'cada IP hace dos o tres intentos, ninguna llega al maximo, y el conjunto prueba miles de '
                . 'contrasenas. El bloqueo por IP no sirve de mucho aqui.',
                [
                    ['do' => 'Comprueba lo primero que nadie haya entrado',
                     'cmd' => 'grep "Accepted " /var/log/auth.log | tail -20'],
                    ['do' => 'Mira si las direcciones comparten operador o pais: si es asi, se corta por prefijo',
                     'cmd' => 'journalctl -u ssh --since today | grep -oE "from [0-9.]+" | sort -u | wc -l'],
                    ['do' => 'Baja el maximo de intentos y alarga la ventana de deteccion mientras dure',
                     'cmd' => 'plesk bin ip_ban --update -max_retries 3 -ban_time_window 86400 -ban_period 86400'],
                    ['do' => 'Si el ataque va contra SSH y usas claves, esta es la ocasion de desactivar la '
                           . 'autenticacion por contrasena: la campana se queda sin objetivo.'],
                ],
                'journalctl -u ssh --since today | grep -oE "from [0-9.]+" | sort -u | wc -l'
            )
        );
    }

    return [
        'window_days'   => CENT_HISTORY_DAYS,
        'today'         => $todayTotal,
        'yesterday'     => $days[$yesterday]['total'] ?? 0,
        'last7'         => $total7,
        'daily_avg'     => round($avg, 1),
        'unique_ips_7d' => count($ips),
        'series_daily'  => $series,
        'series_hourly' => $hourly,
        'top_ips'       => $topIps,
        'top_users'     => array_map(fn($u, $c) => ['user' => $u, 'count' => $c],
                            array_keys(array_slice($users, 0, 25, true)),
                            array_values(array_slice($users, 0, 25, true))),
        'by_country'    => array_map(fn($c, $n) => ['cc' => $c, 'count' => $n],
                            array_keys(array_slice($byCc, 0, 20, true)),
                            array_values(array_slice($byCc, 0, 20, true))),
        'by_asn'        => $asnList,
        'by_service'    => array_map(fn($s, $n) => ['service' => $s, 'count' => $n],
                            array_keys($services), array_values($services)),
        'successes'     => $succ,
        'findings'      => $findings,
    ];
}
