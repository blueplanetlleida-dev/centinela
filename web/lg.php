<?php
/**
 * Centinela - looking glass publico.
 *
 * Pagina independiente del panel: no expone datos internos del servidor, solo
 * ejecuta herramientas de diagnostico contra destinos publicos.
 *
 * Defensas: catalogo cerrado de herramientas, validacion y resolucion previa
 * del destino, bloqueo de rangos internos en cada salto, ejecucion sin shell,
 * limite de frecuencia por IP y verificacion en la primera consulta.
 */

declare(strict_types=1);
require __DIR__ . '/lib/boot.php';
require __DIR__ . '/lib/captcha.php';
require __DIR__ . '/lib/safeexec.php';
require __DIR__ . '/lib/lgtools.php';
require __DIR__ . '/lib/lgtools2.php';

send_security_headers();

if (empty($CFG['lg']['enabled'])) {
    http_response_code(404);
    exit('No disponible.');
}
if (empty($CFG['lg']['public'])) {
    require __DIR__ . '/lib/auth.php';
    require_auth();
}

const LG_PASS_COOKIE = 'centinela_lg';

/** Emite un pase firmado tras superar la verificacion. */
function lg_pass_issue(int $ttl = 3600): void
{
    $exp = time() + $ttl;
    $sig = hash_hmac('sha256', 'lg.' . $exp, captcha_key());
    setcookie(LG_PASS_COOKIE, $exp . '.' . $sig, [
        'expires'  => $exp,
        'path'     => '/',
        'secure'   => is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function lg_pass_valid(): bool
{
    $p = explode('.', (string) ($_COOKIE[LG_PASS_COOKIE] ?? ''));
    if (count($p) !== 2) {
        return false;
    }
    [$exp, $sig] = $p;
    if ((int) $exp < time()) {
        return false;
    }
    return hash_equals(hash_hmac('sha256', 'lg.' . (int) $exp, captcha_key()), $sig);
}

/**
 * Identidad publica del nodo. Se cachea un dia: son datos que no cambian
 * y no conviene resolverlos en cada visita.
 */
function lg_node_info(): array
{
    global $CFG;
    $file = rtrim($CFG['state_dir'], '/') . '/lg_node.json';
    if (is_readable($file)) {
        $d = json_decode((string) @file_get_contents($file), true);
        if (is_array($d) && (time() - (int) ($d['at'] ?? 0)) < 86400) {
            return $d;
        }
    }

    $info = ['at' => time(), 'asn' => null, 'org' => null, 'cc' => null];

    // La IP de origen NO se publica: el sitio esta detras de Cloudflare y
    // mostrarla permitiria saltarse esa proteccion y atacar el origen directo.
    // Solo se resuelve internamente para etiquetar el ASN/operador del nodo.
    $state = read_state();
    $origin = $state['mail']['ip'] ?? ($_SERVER['SERVER_ADDR'] ?? null);

    if ($origin && filter_var($origin, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $rev = implode('.', array_reverse(explode('.', $origin))) . '.origin.asn.cymru.com';
        foreach (@dns_get_record($rev, DNS_TXT) ?: [] as $r) {
            $parts = array_map('trim', explode('|', (string) ($r['txt'] ?? '')));
            if (count($parts) >= 3) {
                $info['asn'] = trim(explode(' ', $parts[0])[0]);
                $info['cc']  = $parts[2];
                break;
            }
        }
        if ($info['asn']) {
            foreach (@dns_get_record('AS' . $info['asn'] . '.asn.cymru.com', DNS_TXT) ?: [] as $r) {
                $p = explode('|', (string) ($r['txt'] ?? ''));
                if (isset($p[4])) {
                    $info['org'] = trim($p[4]);
                    break;
                }
            }
        }
    }

    @file_put_contents($file, json_encode($info), LOCK_EX);
    return $info;
}

// ============================================================== consulta ====
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $ip      = client_ip();
    $perMin  = (int) ($CFG['lg']['per_minute'] ?? 10);
    $perHour = (int) ($CFG['lg']['per_hour'] ?? 60);

    if (!rl_hit('lg:m:' . $ip, $perMin, 60)) {
        json_out(['ok' => false, 'error' => "Has alcanzado el limite de {$perMin} consultas por minuto. Espera un momento."], 429);
    }
    if (!rl_hit('lg:h:' . $ip, $perHour, 3600)) {
        json_out(['ok' => false, 'error' => "Has alcanzado el limite de {$perHour} consultas por hora."], 429);
    }

    $cmd    = (string) ($_POST['cmd'] ?? '');
    $target = (string) ($_POST['target'] ?? '');

    if (!lg_pass_valid()) {
        $ctok = (string) ($_POST['ctoken'] ?? '');
        $cans = (string) ($_POST['canswer'] ?? '');
        if ($ctok === '' || !captcha_check($ctok, $cans)) {
            json_out([
                'ok' => false,
                'need_captcha' => true,
                'captcha' => captcha_make(),
                'error' => $cans === '' ? '' : 'La respuesta no es correcta.',
            ]);
        }
        lg_pass_issue();
    }

    $options = [];
    if ($cmd === 'port' || $cmd === 'tls') {
        $options['port'] = (int) ($_POST['port'] ?? ($cmd === 'tls' ? 443 : 0));
    }
    if ($cmd === 'dns' || $cmd === 'dnsprop') {
        $type = strtoupper((string) ($_POST['type'] ?? 'A'));
        $options['type'] = in_array($type, ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA', 'SRV', 'PTR', 'DS', 'DNSKEY'], true) ? $type : 'A';
    }

    $t0  = microtime(true);
    $res = lg_run($cmd, $target, $options);
    $ms  = (int) round((microtime(true) - $t0) * 1000);

    json_out([
        'ok'        => $res['ok'],
        'error'     => $res['error'],
        'output'    => $res['output'],
        'blocks'    => $res['blocks'] ?? [],
        'meta'      => $res['meta'],
        'ms'        => $ms,
        'remaining' => rl_remaining('lg:m:' . $ip, $perMin, 60),
    ]);
}

// ================================================================ pagina ====
$cmds    = lg_commands();
$captcha = lg_pass_valid() ? null : captcha_make();
$node    = lg_node_info();
$host    = $_SERVER['HTTP_HOST'] ?? php_uname('n');

$groups = [];
foreach ($cmds as $key => $c) {
    $groups[$c['group'] ?? 'Herramientas'][$key] = $c;
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Looking Glass · <?= h($host) ?></title>
<meta name="description" content="Herramientas de diagnostico de red: ping, traceroute, DNS, RDAP, certificados TLS, cabeceras de seguridad, listas negras y puertos.">
<meta name="color-scheme" content="dark">
<link rel="stylesheet" href="<?= asset('assets/lg.css') ?>">
</head>
<body>

<svg style="display:none" aria-hidden="true"><defs>
  <g id="i-pulse" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M1 8h3.5l2-5 3 10 2.5-5H15"/></g>
  <g id="i-route" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="3.5" cy="3.5" r="2"/><circle cx="12.5" cy="12.5" r="2"/><path d="M3.5 5.5v3a3 3 0 0 0 3 3h3.5"/></g>
  <g id="i-grid" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="1.5" y="1.5" width="5" height="5" rx="1"/><rect x="9.5" y="1.5" width="5" height="5" rx="1"/><rect x="1.5" y="9.5" width="5" height="5" rx="1"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/></g>
  <g id="i-plug" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M5 1.5v4M11 1.5v4M3.5 5.5h9v3a4.5 4.5 0 0 1-9 0zM8 13v2"/></g>
  <g id="i-dns" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="6.5"/><path d="M1.5 8h13M8 1.5a10 10 0 0 1 0 13a10 10 0 0 1 0-13z"/></g>
  <g id="i-swap" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M2 5h10l-2.5-2.5M14 11H4l2.5 2.5"/></g>
  <g id="i-book" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 2.5h7a2 2 0 0 1 2 2v9a1.5 1.5 0 0 0-1.5-1.5h-7.5z"/><path d="M11.5 4.5h2v9h-8"/></g>
  <g id="i-globe2" fill="none" stroke-width="1.4" stroke-linecap="round"><circle cx="8" cy="8" r="6.2"/><path d="M1.8 8h12.4M8 1.8v12.4" opacity=".5"/><ellipse cx="8" cy="8" rx="2.8" ry="6.2"/><circle cx="12.2" cy="4.4" r="1.4" fill="currentColor" stroke="none"/></g>
  <g id="i-broadcast" fill="none" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="8" r="1.4" fill="currentColor" stroke="none"/><path d="M5.2 5.2a4 4 0 0 0 0 5.6M10.8 5.2a4 4 0 0 1 0 5.6M3.2 3.2a6.8 6.8 0 0 0 0 9.6M12.8 3.2a6.8 6.8 0 0 1 0 9.6"/></g>
  <g id="i-keychain" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="8" r="2.6"/><path d="M7.6 8H13l1 1.4M11 8v2.2"/></g>
  <g id="i-stamp" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3.2a2 2 0 0 1 4 0c0 1.3-1 1.9-1 3.1h-2C7 5.1 6 4.5 6 3.2ZM4 9.2h8M3 13h10v-1.6a1.2 1.2 0 0 0-1.2-1.2H4.2A1.2 1.2 0 0 0 3 11.4Z"/></g>
  <g id="i-envelope" fill="none" stroke-width="1.5" stroke-linejoin="round"><rect x="2" y="3.5" width="12" height="9" rx="1.4"/><path d="m2.6 4.4 5.4 4 5.4-4"/></g>
  <g id="i-fingerprint" fill="none" stroke-width="1.3" stroke-linecap="round"><path d="M4.2 6.2a4.6 4.6 0 0 1 7.6 0M5.6 8.4a3 3 0 0 1 4.8 0M8 8v4M6.4 10.4v1.6M9.6 9.2v3.2M3.4 9.6C3.4 6 5.4 4 8 4"/></g>
  <g id="i-ruler" fill="none" stroke-width="1.5" stroke-linejoin="round"><rect x="2" y="5" width="12" height="6" rx="1" transform="rotate(-0 8 8)"/><path d="M4.5 5v2M6.5 5v2.6M8.5 5v2M10.5 5v2.6M12.5 5v2"/></g>
  <g id="i-radar" fill="none" stroke-width="1.5" stroke-linecap="round"><path d="M8 8 12.4 3.6M8 8m-6.2 0a6.2 6.2 0 1 0 12.4 0 6.2 6.2 0 1 0-12.4 0"/><path d="M8 8m-3.4 0a3.4 3.4 0 1 0 6.8 0 3.4 3.4 0 1 0-6.8 0" opacity=".55"/><circle cx="8" cy="8" r="1" fill="currentColor" stroke="none"/></g>
  <g id="i-globe" fill="none" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="8" r="6.2"/><ellipse cx="8" cy="8" rx="2.8" ry="6.2"/><path d="M1.8 8h12.4M2.7 4.9h10.6M2.7 11.1h10.6"/></g>
  <g id="i-network" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="3" r="1.8"/><circle cx="3" cy="13" r="1.8"/><circle cx="13" cy="13" r="1.8"/><path d="M8 4.8v3.7M8 8.5 3.8 11.6M8 8.5l4.2 3.1"/></g>
  <g id="i-lock" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="7" width="11" height="7.5" rx="1.5"/><path d="M5 7V4.8a3 3 0 0 1 6 0V7"/></g>
  <g id="i-shield" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1.5 13.5 4v4c0 3.4-2.3 5.9-5.5 6.9C4.8 13.9 2.5 11.4 2.5 8V4z"/><path d="m5.8 8 1.6 1.6L10.4 6.6"/></g>
  <g id="i-ban" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="6.3"/><path d="m3.7 3.7 8.6 8.6"/></g>
  <g id="i-mail" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="1.5" y="3" width="13" height="10" rx="1.5"/><path d="m1.8 4 6.2 4.6L14.2 4"/></g>
  <g id="i-search" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="7" cy="7" r="5"/><path d="m10.8 10.8 3.7 3.7"/></g>
  <g id="i-radar" fill="none" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M8 8 12.6 3.4"/><circle cx="8" cy="8" r="6.3"/><circle cx="8" cy="8" r="3"/></g>
</defs></svg>

<header class="masthead">
  <div class="shell">
    <div class="mast-top">
      <div class="logo">
        <div class="logo-mark">
          <svg viewBox="0 0 16 16" stroke="#fff"><use href="#i-radar"/></svg>
        </div>
        <div class="logo-text">
          <div class="name">Centinela</div>
          <div class="kicker">Looking Glass</div>
        </div>
      </div>
      <div class="grow"></div>
      <div class="node-chip">
        <span class="live" aria-hidden="true"></span>
        <span>Nodo operativo &middot; <b><?= h($node['cc'] ?? '—') ?></b></span>
      </div>
    </div>

    <h1 class="mast-title">Diagn&oacute;stico de red y seguridad</h1>
    <p class="mast-sub">
      Doce herramientas para inspeccionar conectividad, nombres de dominio y postura
      de seguridad de cualquier destino p&uacute;blico de Internet, ejecutadas desde este nodo.
    </p>

    <div class="node-facts">
      <div class="node-fact">
        <div class="k">Nodo</div>
        <div class="v mono"><?= h($host) ?></div>
      </div>
      <?php if (!empty($node['asn'])): ?>
      <div class="node-fact">
        <div class="k">Sistema aut&oacute;nomo</div>
        <div class="v mono">AS<?= h($node['asn']) ?></div>
      </div>
      <?php endif; ?>
      <?php if (!empty($node['org'])): ?>
      <div class="node-fact">
        <div class="k">Operador</div>
        <div class="v"><?= h(mb_strimwidth((string) $node['org'], 0, 40, '…')) ?></div>
      </div>
      <?php endif; ?>
      <div class="node-fact">
        <div class="k">L&iacute;mite</div>
        <div class="v"><?= (int) ($CFG['lg']['per_minute'] ?? 10) ?>/min &middot; <?= (int) ($CFG['lg']['per_hour'] ?? 60) ?>/h</div>
      </div>
    </div>
  </div>
</header>

<main>
<div class="shell">

  <div class="tool-groups">
    <?php foreach ($groups as $groupName => $tools): ?>
    <section>
      <h2 class="section-label"><?= h($groupName) ?></h2>
      <div class="tool-grid" role="group" aria-label="Herramientas de <?= h($groupName) ?>">
        <?php foreach ($tools as $key => $c): ?>
        <button type="button" class="tool" data-cmd="<?= h($key) ?>"
                data-desc="<?= h($c['desc']) ?>" data-hint="<?= h($c['hint'] ?? '') ?>"
                data-field="<?= h($c['field'] ?? '') ?>" data-label="<?= h($c['label']) ?>"
                data-icon="<?= h($c['icon']) ?>"
                aria-pressed="false">
          <span class="ico"><svg viewBox="0 0 16 16"><use href="#i-<?= h($c['icon']) ?>"/></svg></span>
          <span class="body">
            <span class="t"><?= h($c['label']) ?></span>
            <span class="d"><?= h($c['desc']) ?></span>
          </span>
        </button>
        <?php endforeach; ?>
      </div>
    </section>
    <?php endforeach; ?>
  </div>

  <form class="query" id="lgform" autocomplete="off">
    <div class="query-head">
      <span class="active-tool">
        <svg viewBox="0 0 16 16" id="active-icon" aria-hidden="true"><use href="#i-pulse"/></svg>
        <span id="active-label">Ping</span>
      </span>
      <span class="active-desc" id="active-desc">Latencia y p&eacute;rdida de paquetes hasta el destino</span>
    </div>

    <div class="query-row">
      <div class="field-wrap">
        <span class="prefix" aria-hidden="true">&rsaquo;</span>
        <label class="sr-only" for="target">Destino</label>
        <input type="text" id="target" name="target" required maxlength="253"
               spellcheck="false" autocapitalize="none" placeholder="1.1.1.1 o ejemplo.com">
      </div>

      <div class="opt-field" id="opt-port" hidden>
        <label class="sr-only" for="port">Puerto</label>
        <input type="number" id="port" name="port" min="1" max="65535" value="443" placeholder="Puerto">
      </div>

      <div class="opt-field" id="opt-type" hidden>
        <label class="sr-only" for="type">Tipo de registro</label>
        <select id="type" name="type">
          <?php foreach (['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA', 'SRV', 'DS', 'DNSKEY'] as $t): ?>
            <option value="<?= $t ?>"><?= $t ?></option>
          <?php endforeach; ?>
        </select>
      </div>

      <button type="submit" class="btn btn-primary" id="run">
        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><use href="#i-search"/></svg>
        Ejecutar
      </button>
    </div>

    <div class="captcha-row" id="captcha-row" <?= $captcha ? '' : 'hidden' ?>>
      <label for="canswer">Verificaci&oacute;n: <span class="q" id="cquestion"><?= h($captcha['question'] ?? '') ?></span></label>
      <input type="text" id="canswer" name="canswer" inputmode="numeric" autocomplete="off" aria-describedby="cq-help">
      <span id="cq-help" class="sr-only">Resuelve la operaci&oacute;n para continuar</span>
      <input type="hidden" id="ctoken" name="ctoken" value="<?= h($captcha['token'] ?? '') ?>">
    </div>

    <div class="hintline">
      <span><kbd>/</kbd> ir al destino</span>
      <span><kbd>Enter</kbd> ejecutar</span>
      <span><kbd>Esc</kbd> limpiar</span>
      <span id="quota"></span>
    </div>
  </form>

  <div class="results" id="results" aria-live="polite">
    <div class="placeholder">
      <svg viewBox="0 0 16 16" fill="none" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><use href="#i-radar"/></svg>
      <p>Elige una herramienta, escribe un destino y pulsa Ejecutar.</p>
    </div>
  </div>

  <section class="history" id="history" hidden>
    <h2 class="section-label">Consultas de esta sesi&oacute;n</h2>
    <div class="history-list" id="history-list"></div>
  </section>

  <footer class="foot">
    <div>
      <h4>Qu&eacute; hace esta herramienta</h4>
      <p>Ejecuta comprobaciones de red desde este servidor hacia el destino que indiques.
         Sirve para diagnosticar rutas, resoluci&oacute;n de nombres, certificados y
         configuraci&oacute;n de correo desde un punto de vista externo al tuyo.</p>
    </div>
    <div>
      <h4>L&iacute;mites</h4>
      <ul>
        <li>Solo destinos p&uacute;blicos: las direcciones privadas y reservadas est&aacute;n bloqueadas.</li>
        <li><?= (int) ($CFG['lg']['per_minute'] ?? 10) ?> consultas por minuto y <?= (int) ($CFG['lg']['per_hour'] ?? 60) ?> por hora.</li>
        <li>Las herramientas son de solo lectura: observan, no modifican nada.</li>
      </ul>
    </div>
    <div>
      <h4>Privacidad</h4>
      <p>No se guardan las consultas. Solo se registra un contador por direcci&oacute;n IP
         para aplicar el l&iacute;mite de frecuencia, que caduca solo.
         El historial que ves vive &uacute;nicamente en tu navegador.</p>
    </div>
  </footer>

  <div class="foot-bottom">
    <span>Centinela v<?= h(CENT_VERSION) ?> &middot; looking glass</span>
    <span><?= h($host) ?></span>
  </div>

</div>
</main>

<script src="<?= asset('assets/lg.js') ?>"></script>
</body>
</html>
