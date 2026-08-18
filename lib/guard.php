<?php
/**
 * Centinela - geo-valla de los servicios de administracion.
 *
 * La politica dice desde donde es legitimo administrar el servidor: paises
 * y rangos permitidos. Todo lo demas que toque SSH o el panel se banea al
 * primer intento fallido, sin esperar a que acumule los cinco de fail2ban.
 *
 * Es deliberadamente reactiva, no un filtro previo en el firewall: el
 * administrador entra desde redes dinamicas (casa, Starlink, Tailscale) y una
 * allowlist estatica acabaria dejandole fuera. Con la valla, el atacante
 * consigue un intento y pierde la IP; el administrador legitimo desde un
 * origen imprevisto solo genera una alerta, nunca un bloqueo.
 *
 * La politica vive en /etc/centinela/ssh_guard.json, propiedad de root, y se
 * edita solo con centinela-admin: si la web pudiera reescribirla, un panel
 * comprometido podria autoexcluirse de la valla.
 */

declare(strict_types=1);

/** Ruta del fichero de politica. */
function guard_policy_file(): string
{
    return '/etc/centinela/ssh_guard.json';
}

/**
 * Politica vigente, cacheada por proceso.
 *
 * Devuelve siempre la estructura completa: si el fichero no existe o esta
 * roto, la valla queda desactivada y no se inventa nada.
 */
function guard_policy(?array $set = null): array
{
    static $policy = null;
    if ($set !== null) {
        $policy = $set;   // solo para pruebas
    }
    if ($policy !== null) {
        return $policy;
    }
    $base = [
        'enabled'         => false,
        'action'          => 'ban',      // 'ban' | 'observe'
        'services'        => ['ssh', 'panel'],
        'allow_countries' => [],
        'allow_ips'       => [],
        'jail'            => 'plesk-permanent-ban',
    ];
    $raw = @file_get_contents(guard_policy_file());
    $d   = $raw !== false ? json_decode($raw, true) : null;
    $policy = is_array($d) ? array_replace($base, array_intersect_key($d, $base)) : $base;
    $policy['allow_countries'] = array_map('strtoupper', array_map('strval', (array) $policy['allow_countries']));
    $policy['allow_ips']       = array_values(array_map('strval', (array) $policy['allow_ips']));
    return $policy;
}

/** ¿Cae la IP en alguno de los CIDR (o direcciones sueltas) de la lista? */
function guard_ip_in_list(string $ip, array $cidrs): bool
{
    $ipBin = @inet_pton($ip);
    if ($ipBin === false) {
        return false;
    }
    foreach ($cidrs as $cidr) {
        if (!str_contains($cidr, '/')) {
            if ($cidr === $ip) {
                return true;
            }
            continue;
        }
        [$net, $bits] = explode('/', $cidr, 2);
        $netBin = @inet_pton($net);
        if ($netBin === false || strlen($netBin) !== strlen($ipBin)) {
            continue;
        }
        $bits  = max(0, min(strlen($ipBin) * 8, (int) $bits));
        $bytes = intdiv($bits, 8);
        $rem   = $bits % 8;
        if ($bytes > 0 && strncmp($ipBin, $netBin, $bytes) !== 0) {
            continue;
        }
        if ($rem === 0) {
            return true;
        }
        $mask = ~((1 << (8 - $rem)) - 1) & 0xFF;
        if ((ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask)) {
            return true;
        }
    }
    return false;
}

/**
 * Veredicto de la politica para una IP.
 *
 * 'allowed'  dentro de la politica (o privada/CGNAT: eso no llega de internet)
 * 'denied'   fuera de la politica
 * 'unknown'  sin pais resuelto todavia: la valla espera, no adivina
 */
function guard_verdict(string $ip, array $policy, array $asnCache): string
{
    // Privadas, loopback y CGNAT no son de internet: fuera del alcance.
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return 'allowed';
    }
    if (guard_ip_in_list($ip, $policy['allow_ips'])) {
        return 'allowed';
    }
    $cc = strtoupper((string) ($asnCache[$ip]['cc'] ?? ''));
    if ($cc === '') {
        return 'unknown';
    }
    return in_array($cc, $policy['allow_countries'], true) ? 'allowed' : 'denied';
}

/** ¿Ha tocado esta IP alguno de los servicios vigilados? */
function guard_touches(array $store, string $ip, array $services): bool
{
    foreach ($services as $svc) {
        if (!empty($store['ip_svc'][$ip][$svc])) {
            return true;
        }
    }
    return false;
}

/**
 * Evalua y aplica la geo-valla. Modulo del colector y del vigilante.
 *
 * Corre como root, asi que banea directamente con fail2ban-client; cada baneo
 * queda en actions.log igual que los pedidos desde el panel, con la valla
 * como autor. En modo 'observe' cuenta lo que habria hecho y no toca nada.
 */
function collect_guard(): array
{
    $policy = guard_policy();
    $res = [
        'enabled'  => (bool) $policy['enabled'],
        'action'   => $policy['action'],
        'services' => $policy['services'],
        'allow_countries' => $policy['allow_countries'],
        'allow_ips'       => $policy['allow_ips'],
        'banned_today'    => 0,
        'would_ban'       => 0,
        'pending_geo'     => 0,
        'out_logins'      => [],
        'findings'        => [],
    ];
    if (!$policy['enabled']) {
        return $res;
    }

    $store  = load_event_store();
    $banned = function_exists('fail2ban_banned_map') ? fail2ban_banned_map() : [];

    // Estado propio: a quien ha baneado ya la valla y que dia es.
    $sf    = state_dir() . '/guard_state.json';
    $gs    = is_file($sf) ? (json_decode((string) slurp($sf), true) ?: []) : [];
    $hoy   = date('Y-m-d');
    if (($gs['day'] ?? '') !== $hoy) {
        $gs = ['day' => $hoy, 'banned' => [], 'total' => 0];
    }
    $gs += ['banned' => [], 'total' => 0];

    // ---- intentos fallidos recientes contra servicios vigilados ----------
    $candidatas = [];
    foreach ([date('Y-m-d'), date('Y-m-d', time() - 86400)] as $dia) {
        foreach (array_keys($store['days'][$dia]['ips'] ?? []) as $ip) {
            $candidatas[$ip] = true;
        }
    }

    $denegar = [];
    foreach (array_keys($candidatas) as $ip) {
        if (!guard_touches($store, $ip, $policy['services'])) {
            continue;
        }
        $v = guard_verdict($ip, $policy, $store['asn'] ?? []);
        if ($v === 'unknown') {
            $res['pending_geo']++;
            continue;
        }
        if ($v === 'denied' && empty($banned[$ip]) && empty($gs['banned'][$ip])) {
            $denegar[] = $ip;
        }
    }

    if ($policy['action'] === 'observe') {
        $res['would_ban'] = count($denegar);
    } else {
        foreach (array_slice($denegar, 0, 50) as $ip) {
            $r = run(['/usr/bin/fail2ban-client', 'set', $policy['jail'], 'banip', $ip], 20);
            $linea = sprintf(
                "%s\tban\t%s\t%s\t%s\tgeo-valla\t%s\n",
                date('c'), $ip, $policy['jail'], $r['ok'] ? 'ok' : 'error',
                $r['ok'] ? ('fuera de politica: ' . (($store['asn'][$ip]['cc'] ?? '?')))
                         : trim($r['err'] ?: $r['out'])
            );
            @file_put_contents(state_dir() . '/actions.log', $linea, FILE_APPEND | LOCK_EX);
            if ($r['ok']) {
                $gs['banned'][$ip] = time();
                $gs['total']++;
            }
        }
    }
    $res['banned_today'] = count($gs['banned']);
    write_atomic($sf, json_encode($gs), 0640);

    // ---- accesos correctos fuera de politica -----------------------------
    // Nunca se banean: la unica hipotesis alternativa a una intrusion es que
    // seas tu desde un sitio nuevo, y banearte seria peor que el riesgo.
    $corte = time() - 86400;
    foreach ($store['successes'] ?? [] as $sx) {
        if (($sx['ts'] ?? 0) < $corte) {
            continue;
        }
        if (!in_array($sx['service'] ?? '', $policy['services'], true)) {
            continue;
        }
        if (guard_verdict((string) $sx['ip'], $policy, $store['asn'] ?? []) === 'denied') {
            $res['out_logins'][] = $sx;
        }
    }

    if ($res['out_logins']) {
        $ult = end($res['out_logins']);
        $cc  = $store['asn'][$ult['ip']]['cc'] ?? '?';
        $res['findings'][] = finding(
            'guard.login',
            SEV_CRIT,
            'Acceso correcto desde fuera de la politica de administracion',
            count($res['out_logins']) . ' acceso(s) en 24h. Ultimo: ' . $ult['user'] . '@' . $ult['ip']
                . ' (' . $cc . ') el ' . date('d/m H:i', $ult['ts']) . ' por ' . $ult['method']
                . ' en ' . $ult['service'] . '. La valla no banea accesos correctos: comprueba si eres tu.',
            'Si eres tu, anade el rango o el pais a la politica; si no, rota credenciales ya',
            guide(
                'La geo-valla dice desde donde es normal administrar este servidor. Un acceso correcto desde '
                . 'fuera solo tiene dos explicaciones: eres tu en un sitio imprevisto, o la credencial ya no es '
                . 'solo tuya. Por diseno no se banea, para que un viaje no te deje sin servidor.',
                [
                    ['do' => '¿Eres tu? Anade el origen a la politica y no volvera a avisar',
                     'cmd' => 'centinela-admin guard --allow-ip ' . ((string) $ult['ip']) . '/32'],
                    ['do' => 'Si no lo reconoces, mira que hizo esa sesion',
                     'cmd' => 'last -F | head -20'],
                    ['do' => 'Rota la credencial y corta las sesiones de esa cuenta',
                     'cmd' => 'passwd ' . escapeshellarg((string) $ult['user']) . '; pkill -KILL -u ' . escapeshellarg((string) $ult['user'])],
                    ['do' => 'Y banea la IP desde el panel o a mano',
                     'cmd' => 'fail2ban-client set ' . $policy['jail'] . ' banip ' . ((string) $ult['ip'])],
                ],
                'last -F | head -10'
            )
        );
    }

    if ($policy['action'] === 'observe' && $res['would_ban'] > 0) {
        $res['findings'][] = finding(
            'guard.observe',
            SEV_INFO,
            'Geo-valla en observacion: habria baneado ' . $res['would_ban'] . ' IP(s)',
            'La politica esta definida pero sin aplicar. Ninguna de tus IPs de acceso cae fuera.',
            'Activarla con: centinela-admin guard --enforce'
        );
    }

    return $res;
}
