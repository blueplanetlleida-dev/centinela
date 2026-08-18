<?php
/**
 * Centinela - exportacion del estado a un syslog remoto.
 *
 * Para integrar el servidor en un SIEM o un syslog centralizado sin darle a
 * nadie acceso al panel: al final de cada recogida se emite un resumen de
 * salud y las transiciones de incidencias (nueva, resuelta), filtradas por
 * severidad. Mensajes RFC 5424 con el cuerpo en clave=valor, que cualquier
 * colector (rsyslog, syslog-ng, Graylog, Wazuh) parte sin configurar nada.
 *
 * Se envia directamente por UDP o TCP desde el colector: sin dependencias,
 * sin pasar por el syslog local y sin tocar la configuracion de rsyslog.
 * Un fallo de red no puede romper la recogida: todo va en @ y con timeout.
 */

declare(strict_types=1);

/** Configuracion de la exportacion, con los valores por defecto. */
function sysout_cfg(): array
{
    $c = load_config()['syslog'] ?? [];
    return [
        'enabled'  => (bool) ($c['enabled'] ?? false),
        'server'   => (string) ($c['server'] ?? ''),      // «host» o «host:puerto»
        'proto'    => strtolower((string) ($c['proto'] ?? 'udp')) === 'tcp' ? 'tcp' : 'udp',
        'facility' => max(0, min(23, (int) ($c['facility'] ?? 16))),   // local0
        'min_sev'  => (string) ($c['min_sev'] ?? 'info'), // umbral para incidencias
        'events'   => (array) ($c['events'] ?? ['health', 'finding', 'attacks']),
        'tag'      => (string) ($c['tag'] ?? 'centinela'),
    ];
}

/** Severidad syslog (0-7) para cada severidad de Centinela. */
function sysout_pri(array $cfg, string $sev): int
{
    $map = ['crit' => 2, 'warn' => 4, 'info' => 6, 'ok' => 6];
    return $cfg['facility'] * 8 + ($map[$sev] ?? 6);
}

/** Escapa un valor para el formato clave=valor. */
function sysout_kv(array $pairs): string
{
    $out = [];
    foreach ($pairs as $k => $v) {
        $v = (string) $v;
        if ($v === '' ) {
            continue;
        }
        // Sin saltos de linea (partirian el mensaje) y con comillas si hay espacios
        $v = str_replace(["\n", "\r", "\t"], ' ', $v);
        if (preg_match('/[\s"=]/', $v)) {
            $v = '"' . str_replace('"', "'", $v) . '"';
        }
        $out[] = $k . '=' . $v;
    }
    return implode(' ', $out);
}

/**
 * Envia una tanda de mensajes al servidor configurado.
 *
 * @param array $msgs Lista de ['sev' => string, 'body' => string]
 * @return array{sent:int, error:string}
 */
function sysout_send(array $msgs, ?array $cfg = null): array
{
    $cfg = $cfg ?? sysout_cfg();
    if (!$msgs || $cfg['server'] === '') {
        return ['sent' => 0, 'error' => $cfg['server'] === '' ? 'sin servidor configurado' : ''];
    }

    $host = $cfg['server'];
    $port = 514;
    if (preg_match('/^(.*):(\d+)$/', $host, $m) && !str_contains($m[1], ':')) {
        $host = $m[1];
        $port = (int) $m[2];
    }

    $addr = ($cfg['proto'] === 'tcp' ? 'tcp://' : 'udp://') . $host . ':' . $port;
    $sock = @stream_socket_client($addr, $errno, $errstr, 3);
    if ($sock === false) {
        return ['sent' => 0, 'error' => "no se pudo conectar a {$addr}: {$errstr}"];
    }
    @stream_set_timeout($sock, 3);

    $hostname = php_uname('n');
    $ts       = date('Y-m-d\TH:i:sP');
    $sent     = 0;
    foreach ($msgs as $msg) {
        $pri   = sysout_pri($cfg, (string) ($msg['sev'] ?? 'info'));
        // RFC 5424: <PRI>1 FECHA HOST APP PROCID MSGID SD MSG
        $frame = "<{$pri}>1 {$ts} {$hostname} {$cfg['tag']} - - - " . $msg['body'];
        // En TCP los mensajes van delimitados por salto de linea (octet-stuffing
        // no hace falta para los colectores habituales)
        $ok = @fwrite($sock, $frame . ($cfg['proto'] === 'tcp' ? "\n" : ''));
        if ($ok !== false) {
            $sent++;
        }
    }
    @fclose($sock);
    return ['sent' => $sent, 'error' => ''];
}

/**
 * Exporta el resultado de una recogida: la llama el colector al final.
 *
 * Emite el resumen de salud en cada pasada (serie temporal para el SIEM) y
 * las transiciones de incidencias respecto a la pasada anterior, para que el
 * lado remoto pueda alertar sobre «aparecio X» y no sobre «X sigue ahi».
 */
function sysout_export(array $report): void
{
    $cfg = sysout_cfg();
    if (!$cfg['enabled'] || $cfg['server'] === '') {
        return;
    }

    $rank    = ['info' => 1, 'warn' => 2, 'crit' => 3];
    $minRank = $rank[$cfg['min_sev']] ?? 1;
    $msgs    = [];

    $h = $report['health'] ?? [];
    if (in_array('health', $cfg['events'], true)) {
        $msgs[] = ['sev' => 'info', 'body' => sysout_kv([
            'event'  => 'health',
            'score'  => (int) ($h['score'] ?? 0),
            'grade'  => (string) ($h['grade'] ?? ''),
            'crit'   => (int) ($h['counts']['crit'] ?? 0),
            'warn'   => (int) ($h['counts']['warn'] ?? 0),
            'info'   => (int) ($h['counts']['info'] ?? 0),
        ])];
    }

    if (in_array('attacks', $cfg['events'], true)) {
        $a = $report['attacks'] ?? [];
        $w = $report['web'] ?? [];
        $g = $report['guard'] ?? [];
        $msgs[] = ['sev' => 'info', 'body' => sysout_kv([
            'event'        => 'attacks',
            'auth_today'   => (int) ($a['today'] ?? 0),
            'auth_7d'      => (int) ($a['last7'] ?? 0),
            'unique_ips_7d' => (int) ($a['unique_ips_7d'] ?? 0),
            'loose'        => (int) ($a['loose'] ?? 0),
            'web_susp_7d'  => (int) ($w['suspicious'] ?? 0),
            'web_blocked_7d' => (int) ($w['blocked'] ?? 0),
            'guard_bans_today' => (int) ($g['banned_today'] ?? 0),
        ])];
    }

    if (in_array('finding', $cfg['events'], true)) {
        // Transiciones respecto a la ultima exportacion
        $sf   = state_dir() . '/syslog_state.json';
        $prev = is_file($sf) ? (json_decode((string) slurp($sf), true) ?: []) : [];
        $antes = (array) ($prev['findings'] ?? []);

        $ahora = [];
        foreach ($h['findings'] ?? [] as $f) {
            if (($rank[$f['sev']] ?? 0) < $minRank) {
                continue;
            }
            $ahora[$f['id']] = $f['sev'];
            $estado = !isset($antes[$f['id']]) ? 'new'
                : ($antes[$f['id']] !== $f['sev'] ? 'changed' : null);
            if ($estado !== null) {
                $msgs[] = ['sev' => $f['sev'], 'body' => sysout_kv([
                    'event' => 'finding',
                    'state' => $estado,
                    'id'    => $f['id'],
                    'sev'   => $f['sev'],
                    'title' => (string) $f['title'],
                    'detail' => mb_strimwidth((string) ($f['detail'] ?? ''), 0, 300, '…'),
                ])];
            }
        }
        foreach ($antes as $id => $sev) {
            if (!isset($ahora[$id])) {
                $msgs[] = ['sev' => 'info', 'body' => sysout_kv([
                    'event' => 'finding', 'state' => 'resolved', 'id' => $id,
                ])];
            }
        }
        write_atomic($sf, json_encode(['findings' => $ahora, 'at' => time()]), 0640);
    }

    $r = sysout_send($msgs, $cfg);
    if ($r['error'] !== '') {
        clog('syslog remoto: ' . $r['error']);
    } elseif ($r['sent'] > 0) {
        clog('syslog remoto: ' . $r['sent'] . ' mensaje(s) a ' . $cfg['server']);
    }
}
