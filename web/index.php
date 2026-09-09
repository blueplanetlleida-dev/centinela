<?php
/** Centinela - panel de estado. Requiere sesion. */

declare(strict_types=1);
require __DIR__ . '/lib/boot.php';
require __DIR__ . '/lib/auth.php';
require __DIR__ . '/lib/render.php';

send_security_headers();
require_auth();

$st = read_state();
$age = state_age($st);

if ($st === null) {
    http_response_code(503);
    ?>
    <!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Centinela</title><link rel="stylesheet" href="<?= asset('assets/app.css') ?>"></head>
    <body><div class="login-page"><div class="login-box"><div class="card">
    <h1>Sin datos todavia</h1>
    <p class="muted">El colector aun no ha generado el estado. Se ejecuta cada pocos minutos;
    si el problema persiste comprueba el servicio:</p>
    <div class="fix" style="font-family:var(--mono);background:var(--surface-2);padding:10px;border-radius:6px;">
    systemctl status centinela-collect.timer<br>journalctl -u centinela-collect -n 50</div>
    <p style="margin-top:18px;"><a class="btn" href="index.php">Reintentar</a>
    <a class="btn" href="logout.php">Salir</a></p>
    </div></div></div></body></html>
    <?php
    exit;
}

$health = $st['health'] ?? ['score' => 0, 'grade' => '?', 'counts' => [], 'findings' => []];
$sys    = $st['system'] ?? [];
$atk    = $st['attacks'] ?? [];
$counts = $health['counts'] ?? [];
$stale  = $age !== null && $age > 900;
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Centinela · <?= h($sys['hostname'] ?? 'servidor') ?></title>
<link rel="stylesheet" href="<?= asset('assets/app.css') ?>">
</head>
<body data-generated="<?= (int) ($st['generated_at'] ?? 0) ?>" data-csrf="<?= h(csrf_token()) ?>">

<div class="topbar"><div class="inner">
  <div class="brand">
    <span class="dot<?= $stale ? ' stale' : '' ?>"></span>
    Centinela
    <small><?= h($sys['hostname'] ?? '') ?></small>
  </div>
  <div class="spacer"></div>
  <div class="meta">
    <span>Datos de <span id="age"><?= h(ui_ago((int) ($st['generated_at'] ?? 0))) ?></span></span>
    <span class="muted">·</span>
    <span class="muted"><?= h($sys['os'] ?? '') ?></span>
  </div>
  <a class="btn" href="index.php">Actualizar</a>
  <?php if (!empty($CFG['lg']['enabled'])): ?><a class="btn" href="lg.php">Looking glass</a><?php endif; ?>
  <a class="btn" href="logout.php">Salir</a>
</div></div>

<div class="wrap">

<?php if ($stale): ?>
<div class="alert warn" style="margin-bottom:18px;">
  <span aria-hidden="true">⚠</span>
  <span>Los datos tienen <?= h(ui_duration((int) $age)) ?>. El colector podria estar parado:
  comprueba <code>systemctl status centinela-collect.timer</code>.</span>
</div>
<?php endif; ?>

<?php
// Franja de incidente: lo critico no puede quedar a la altura del resto, y
// menos en un panel que se mira de un vistazo desde el movil.
$criticas = array_values(array_filter($health['findings'] ?? [], fn($f) => ($f['sev'] ?? '') === 'crit'));
if ($criticas): ?>
<div class="alert err incident">
  <span aria-hidden="true">▲</span>
  <span><strong><?= count($criticas) ?> incidencia(s) critica(s) sin resolver.</strong>
  <?= h(implode(' · ', array_map(fn($f) => $f['title'], array_slice($criticas, 0, 2)))) ?>.
  <a href="#incidencias">Ver que hacer</a></span>
</div>
<?php endif; ?>

<?php
// Aviso de version nueva disponible (lo deja centinela-update).
$upFile = rtrim($CFG['state_dir'], '/') . '/update_available.json';
$upInfo = is_file($upFile) ? json_decode((string) file_get_contents($upFile), true) : null;
if (is_array($upInfo) && !empty($upInfo['latest'])): ?>
<div class="alert info" style="margin-bottom:14px;">
  <span aria-hidden="true">↑</span>
  <span>Centinela <strong><?= h($upInfo['latest']) ?></strong> disponible
  (tienes la <?= h($upInfo['current'] ?? '') ?>).
  <?php if (!empty($upInfo['url'])): ?><a href="<?= h($upInfo['url']) ?>" target="_blank" rel="noopener noreferrer">Ver los cambios</a><?php endif; ?></span>
</div>
<?php endif; ?>

<!-- ============================================================ SALUD === -->
<div class="grid cols-2" style="align-items:stretch;">
  <div class="card">
    <h2>Salud global</h2>
    <div class="health">
      <?= ui_gauge((int) $health['score'], (string) $health['grade']) ?>
      <div style="flex:1;min-width:200px;">
        <div class="sev-summary">
          <?php foreach (['crit' => 'Criticos', 'warn' => 'Avisos', 'info' => 'Informativos'] as $k => $lbl):
            $n = (int) ($counts[$k] ?? 0); ?>
          <div class="sev-chip">
            <span class="ico" style="color:<?= ui_sev_color($k) ?>" aria-hidden="true"><?= ui_sev_icon($k) ?></span>
            <span><span class="n" style="color:<?= $n > 0 ? ui_sev_color($k) : 'var(--ink-muted)' ?>"><?= $n ?></span>
            <span class="t"><?= h($lbl) ?></span></span>
          </div>
          <?php endforeach; ?>
        </div>
        <?php $hist = $st['score_history'] ?? []; if (count($hist) > 3): ?>
        <div style="margin-top:16px;">
          <div class="k muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.4px;">Tendencia (30 d)</div>
          <?= ui_sparkline($hist) ?>
        </div>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Resumen operativo</h2>
    <div class="grid cols-2" style="gap:14px;">
      <div class="metric">
        <span class="v"><?= h(ui_duration((int) ($sys['uptime_sec'] ?? 0))) ?></span>
        <span class="k">Encendido</span>
        <?php if (!empty($sys['needs_reboot'])): ?>
          <span class="s" style="color:var(--critical)">Reinicio pendiente</span>
        <?php endif; ?>
      </div>
      <div class="metric">
        <span class="v"><?= nfmt($atk['today'] ?? 0) ?></span>
        <span class="k">Ataques hoy</span>
        <span class="s">media <?= h(str_replace('.', ',', (string) ($atk['daily_avg'] ?? 0))) ?>/dia</span>
      </div>
      <div class="metric">
        <?php $upd = $st['updates'] ?? []; $secN = (int) ($upd['security'] ?? 0); ?>
        <span class="v" style="<?= $secN > 0 ? 'color:var(--critical)' : '' ?>"><?= (int) ($upd['total'] ?? 0) ?></span>
        <span class="k">Actualizaciones</span>
        <span class="s"><?= $secN > 0 ? $secN . ' de seguridad' : 'ninguna de seguridad' ?></span>
      </div>
      <div class="metric">
        <?php $f2b = $st['fail2ban'] ?? []; ?>
        <span class="v"><?= nfmt($f2b['currently_banned'] ?? 0) ?></span>
        <span class="k">IPs bloqueadas</span>
        <span class="s"><?= nfmt($f2b['total_banned'] ?? 0) ?> en total</span>
      </div>
    </div>
  </div>
</div>

<!-- ====================================================== INCIDENCIAS === -->
<h2 class="section-title" id="incidencias">Incidencias
  <span class="muted" style="font-weight:400;">· <?= count($health['findings'] ?? []) ?></span></h2>
<div class="card">
  <?php if (empty($health['findings'])): ?>
    <div class="alert info" style="margin:0;"><span aria-hidden="true">✓</span>
    <span>Sin incidencias. Todas las comprobaciones han pasado.</span></div>
  <?php else: foreach ($health['findings'] as $f) { echo ui_finding($f); } endif; ?>
</div>

<!-- ========================================================= ATAQUES === -->
<h2 class="section-title">Actividad de ataques</h2>
<div class="grid cols-2">
  <div class="card">
    <h2>Intentos fallidos por dia <span class="count">· <?= (int) ($atk['window_days'] ?? 14) ?> dias</span></h2>
    <?php
    $daily = [];
    foreach ($atk['series_daily'] ?? [] as $d) {
        $daily[] = [
            'label' => date('d/m', strtotime($d['date'])),
            'value' => (int) $d['count'],
            'tip'   => date('d/m/Y', strtotime($d['date'])) . ' · ' . nfmt($d['count']) . ' intentos',
        ];
    }
    echo ui_bars($daily, 130, 2);
    ?>
    <div class="legend"><div class="item">
      <span class="swatch" style="background:var(--series)"></span> Intentos de autenticacion fallidos
    </div></div>
  </div>

  <div class="card">
    <h2>Ultimas 48 horas</h2>
    <?php
    $hourly = [];
    foreach ($atk['series_hourly'] ?? [] as $i => $d) {
        $hourly[] = [
            'label' => date('H', strtotime($d['t'])),
            'value' => (int) $d['count'],
            'tip'   => date('d/m H:00', strtotime($d['t'])) . ' · ' . nfmt($d['count']) . ' intentos',
        ];
    }
    echo ui_bars($hourly, 130, 6);
    ?>
    <div class="legend"><div class="item">
      <span class="swatch" style="background:var(--series)"></span> Agrupado por hora
    </div></div>
  </div>
</div>

<div class="grid cols-2" style="margin-top:var(--gap);">
  <div class="card">
    <h2>Origenes principales <span class="count">· 7 dias</span></h2>
    <div class="scroll-x">
    <table class="data">
      <thead><tr><th>IP</th><th>Pais</th><th>Operador</th><th class="num">Intentos</th><th>Ultimo</th>
      <th>Estado</th></tr></thead>
      <tbody>
      <?php
      $tops = array_slice($atk['top_ips'] ?? [], 0, 15);
      $maxIp = $tops ? max(array_column($tops, 'count')) : 1;
      $f2bOn = !empty($st['fail2ban']['active']);
      foreach ($tops as $ip): ?>
        <tr data-ip="<?= h($ip['ip']) ?>">
          <td class="mono nowrap"><?= h($ip['ip']) ?></td>
          <td class="nowrap"><span class="flag"><?= ui_flag($ip['cc'] ?? null) ?></span> <?= h($ip['cc'] ?? '—') ?></td>
          <td><?= $ip['org'] ? h(mb_strimwidth((string) $ip['org'], 0, 34, '…')) : '<span class="muted">desconocido</span>' ?></td>
          <td class="num"><?= ui_inline_bar((int) $ip['count'], (int) $maxIp) ?></td>
          <td class="muted nowrap"><?= h(ui_ago($ip['last_seen'] ?? null)) ?></td>
          <td class="nowrap"><?= ui_ban_cell($ip, $f2bOn) ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$tops): ?><tr><td colspan="6" class="empty">Sin ataques registrados.</td></tr><?php endif; ?>
      </tbody>
    </table>
    </div>
  </div>

  <div class="card">
    <h2>Usuarios mas probados</h2>
    <div class="scroll-x">
    <table class="data">
      <thead><tr><th>Usuario</th><th class="num">Intentos</th></tr></thead>
      <tbody>
      <?php
      $tu = array_slice($atk['top_users'] ?? [], 0, 15);
      $maxU = $tu ? max(array_column($tu, 'count')) : 1;
      foreach ($tu as $u): ?>
        <tr><td class="mono"><?= h($u['user']) ?></td>
        <td class="num"><?= ui_inline_bar((int) $u['count'], (int) $maxU) ?></td></tr>
      <?php endforeach; ?>
      <?php if (!$tu): ?><tr><td colspan="2" class="empty">Sin datos.</td></tr><?php endif; ?>
      </tbody>
    </table>
    </div>
  </div>
</div>

<div class="grid cols-2" style="margin-top:var(--gap);">
  <div class="card">
    <h2>Por pais</h2>
    <div class="scroll-x">
    <table class="data">
      <tbody>
      <?php
      $bc = array_slice($atk['by_country'] ?? [], 0, 12);
      $maxC = $bc ? max(array_column($bc, 'count')) : 1;
      foreach ($bc as $c): ?>
        <tr>
          <td class="nowrap" style="width:70px;"><span class="flag"><?= ui_flag($c['cc']) ?></span> <?= h($c['cc']) ?></td>
          <td class="num"><?= ui_inline_bar((int) $c['count'], (int) $maxC) ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$bc): ?><tr><td class="empty">Sin datos de geolocalizacion todavia.</td></tr><?php endif; ?>
      </tbody>
    </table>
    </div>
  </div>

  <div class="card">
    <h2>Por operador de red</h2>
    <div class="scroll-x">
    <table class="data">
      <thead><tr><th>ASN</th><th>Operador</th><th class="num">Intentos</th></tr></thead>
      <tbody>
      <?php foreach (array_slice($atk['by_asn'] ?? [], 0, 10) as $a): ?>
        <tr>
          <td class="mono nowrap"><?= h($a['asn']) ?></td>
          <td><?= h(mb_strimwidth((string) ($a['org'] ?: 'desconocido'), 0, 36, '…')) ?></td>
          <td class="num"><?= nfmt($a['count']) ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (empty($atk['by_asn'])): ?><tr><td colspan="3" class="empty">Sin datos.</td></tr><?php endif; ?>
      </tbody>
    </table>
    </div>
  </div>
</div>

<?php if (!empty($atk['successes'])): ?>
<div class="card" style="margin-top:var(--gap);">
  <h2>Accesos correctos recientes</h2>
  <div class="scroll-x">
  <table class="data">
    <thead><tr><th>Fecha</th><th>IP</th><th>Usuario</th><th>Metodo</th><th>Servicio</th></tr></thead>
    <tbody>
    <?php foreach (array_slice($atk['successes'], 0, 12) as $s): ?>
      <tr>
        <td class="nowrap muted"><?= h(date('d/m H:i', $s['ts'])) ?></td>
        <td class="mono nowrap"><?= h($s['ip']) ?></td>
        <td><?= h($s['user']) ?></td>
        <td><?= h($s['method']) ?>
          <?php if ($s['method'] === 'contrasena'): ?>
            <span class="tag warn" style="margin-left:4px;"><span aria-hidden="true">!</span> sin clave</span>
          <?php endif; ?>
        </td>
        <td class="muted"><?= h($s['service'] ?? '') ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>
<?php endif; ?>

<!-- ===================================================== ATAQUES WEB === -->
<?php $web = $st['web'] ?? []; if ($web): ?>
<h2 class="section-title">Ataques web
  <span class="muted" style="font-weight:400;">· <?= (int) ($web['window_days'] ?? 7) ?> dias</span></h2>

<?php
  // Un acierto sigue abierto si hoy responde 2xx o el colector aun no lo ha recomprobado.
  $hitAbierto     = fn(array $x): bool => (int) ($x['now'] ?? 0) === 0 || ((int) $x['now'] >= 200 && (int) $x['now'] < 300);
  $hitsAbiertos   = array_values(array_filter($web['hits'] ?? [], $hitAbierto));
  $hitsCorregidos = count($web['hits'] ?? []) - count($hitsAbiertos);
?>
<?php if ($hitsAbiertos): ?>
<div class="alert err" style="margin-bottom:var(--gap);">
  <span aria-hidden="true">▲</span>
  <span><strong>Un escaneo ha encontrado algo.</strong>
  <?= count($hitsAbiertos) ?> peticion(es) a ficheros sensibles respondieron 200:
  <?php $hs = array_slice($hitsAbiertos, 0, 3);
  echo h(implode(' · ', array_map(fn($x) => $x['domain'] . $x['path'], $hs))); ?>.
  Retira esos ficheros del docroot y rota lo que contuvieran.</span>
</div>
<?php elseif ($hitsCorregidos > 0): ?>
<div class="alert info" style="margin-bottom:var(--gap);">
  <span aria-hidden="true">✓</span>
  <span><strong>Corregido.</strong>
  <?= $hitsCorregidos ?> peticion(es) a ficheros sensibles respondieron 200 en la ventana, pero esas rutas ya no se sirven:
  <?php $hs = array_slice($web['hits'], 0, 3);
  echo h(implode(' · ', array_map(fn($x) => $x['domain'] . $x['path'] . ' (hoy ' . (int) ($x['now'] ?? 0) . ')', $hs))); ?>.
  Si contenian credenciales, rotalas.</span>
</div>
<?php endif; ?>

<div class="grid cols-4">
  <div class="card"><div class="metric">
    <span class="v"><?= nfmt($web['suspicious'] ?? 0) ?></span>
    <span class="k">Peticiones sospechosas</span>
    <span class="s">escaneos, rutas de exploit y errores 4xx</span>
  </div></div>
  <div class="card"><div class="metric">
    <span class="v"><?= nfmt($web['blocked'] ?? 0) ?></span>
    <span class="k">Bloqueadas por ModSecurity</span>
    <span class="s">cortadas antes de llegar al sitio</span>
  </div></div>
  <div class="card"><div class="metric">
    <span class="v"><?= nfmt(count($web['top_ips'] ?? [])) ?></span>
    <span class="k">IPs implicadas</span>
    <span class="s">las mas activas de la ventana</span>
  </div></div>
  <div class="card"><div class="metric">
    <span class="v" style="color:<?= $hitsAbiertos ? 'var(--critical)' : 'var(--good)' ?>">
      <?= nfmt(count($hitsAbiertos)) ?></span>
    <span class="k">Aciertos</span>
    <span class="s">rutas sensibles que responden 200<?= $hitsCorregidos > 0 ? ' · ' . nfmt($hitsCorregidos) . ' ya corregida(s)' : '' ?></span>
  </div></div>
</div>

<div class="grid cols-2" style="margin-top:var(--gap);">
  <div class="card">
    <h2>Rutas mas buscadas</h2>
    <div class="scroll-x">
    <table class="data">
      <thead><tr><th>Ruta</th><th class="num">Peticiones</th></tr></thead>
      <tbody>
      <?php
      $wp = array_slice($web['top_paths'] ?? [], 0, 15);
      $maxP = $wp ? max(array_column($wp, 'count')) : 1;
      foreach ($wp as $r): ?>
        <tr><td class="mono"><?= h(mb_strimwidth((string) $r['path'], 0, 52, '…')) ?></td>
        <td class="num"><?= ui_inline_bar((int) $r['count'], (int) $maxP) ?></td></tr>
      <?php endforeach; ?>
      <?php if (!$wp): ?><tr><td colspan="2" class="empty">Sin peticiones sospechosas.</td></tr><?php endif; ?>
      </tbody>
    </table>
    </div>
    <?php if (!empty($web['by_cat'])): ?>
    <div class="legend" style="margin-top:10px;">
      <?php foreach ($web['by_cat'] as $cat => $n): ?>
        <div class="item"><span class="tag info"><?= h($cat) ?></span> <?= nfmt($n) ?></div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2>Quien escanea <span class="count">· <?= (int) ($web['window_days'] ?? 7) ?> dias</span></h2>
    <div class="scroll-x">
    <table class="data">
      <thead><tr><th>IP</th><th class="num">Peticiones</th><th>Busca</th><th>Ultimo</th><th>Estado</th></tr></thead>
      <tbody>
      <?php
      $wi = array_slice($web['top_ips'] ?? [], 0, 12);
      $maxW = $wi ? max(array_column($wi, 'count')) : 1;
      $f2bOn = !empty($st['fail2ban']['active']);
      foreach ($wi as $ip):
        $cats = (array) ($ip['cats'] ?? []);
        arsort($cats);
        $princ = array_slice(array_keys($cats), 0, 2); ?>
        <tr data-ip="<?= h($ip['ip']) ?>">
          <td class="mono nowrap"><?= h($ip['ip']) ?></td>
          <td class="num"><?= ui_inline_bar((int) $ip['count'], (int) $maxW) ?></td>
          <td class="nowrap"><?php foreach ($princ as $c): ?><span class="tag info"><?= h($c) ?></span> <?php endforeach; ?></td>
          <td class="muted nowrap"><?= h(ui_ago($ip['last_seen'] ?? null)) ?></td>
          <td class="nowrap"><?= ui_ban_cell($ip, $f2bOn) ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$wi): ?><tr><td colspan="5" class="empty">Sin actividad registrada.</td></tr><?php endif; ?>
      </tbody>
    </table>
    </div>
    <?php if (!empty($web['by_domain'])): ?>
    <p class="muted" style="font-size:12.5px;margin:12px 0 0;">Mas atacados:
      <?= h(implode(', ', array_map(fn($d) => $d['domain'] . ' (' . $d['count'] . ')',
          array_slice($web['by_domain'], 0, 3)))) ?></p>
    <?php endif; ?>
  </div>
</div>
<?php endif; ?>

<!-- ========================================================= DEFENSAS === -->
<h2 class="section-title">Defensas activas</h2>
<div class="grid cols-4">
  <div class="card">
    <h2>fail2ban</h2>
    <?php $f2b = $st['fail2ban'] ?? []; if (empty($f2b['installed'])): ?>
      <div class="alert err" style="margin:0;"><span aria-hidden="true">✕</span><span>No instalado</span></div>
    <?php elseif (empty($f2b['active'])): ?>
      <div class="alert err" style="margin:0;"><span aria-hidden="true">✕</span><span>Instalado pero parado</span></div>
    <?php else: ?>
      <div class="scroll-x"><table class="data">
        <thead><tr><th>Jail</th><th class="num">Ahora</th><th class="num">Total</th></tr></thead>
        <tbody>
        <?php foreach (array_slice($f2b['jails'] ?? [], 0, 14) as $j): ?>
          <tr><td class="mono"><?= h($j['name']) ?></td>
          <td class="num"<?= $j['currently'] > 0 ? ' style="color:var(--warning);font-weight:600"' : '' ?>><?= nfmt($j['currently']) ?></td>
          <td class="num muted"><?= nfmt($j['total']) ?></td></tr>
        <?php endforeach; ?>
        </tbody>
      </table></div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2>Geo-valla</h2>
    <?php
    $g = $st['guard'] ?? [];
    // Guia de configuracion: se ensena siempre, con los pasos que tocan
    // segun el estado. Los comandos son de consola a proposito: la politica
    // solo la escribe root, nunca esta web.
    $guiaValla = empty($g['enabled'])
        ? [
            'why'   => 'La geo-valla define desde donde es legitimo administrar este servidor: paises y '
                     . 'rangos permitidos. Todo lo demas que falle contra SSH o el panel se banea al primer '
                     . 'intento. Se configura por consola como root; el panel solo la muestra.',
            'steps' => [
                ['do' => 'Permite tu pais', 'cmd' => 'centinela-admin guard --allow-country ES'],
                ['do' => 'Anade tus rangos fijos (oficina, VPN, red del proveedor)',
                 'cmd' => 'centinela-admin guard --allow-ip 203.0.113.0/24'],
                ['do' => 'Simula contra el historico: cuantas IPs habria baneado y, sobre todo, si algun acceso tuyo caeria fuera',
                 'cmd' => 'centinela-admin guard --simulate'],
                ['do' => 'Si prefieres verla trabajar unos dias sin banear, dejala en observacion',
                 'cmd' => 'centinela-admin guard --observe'],
                ['do' => 'Armala', 'cmd' => 'centinela-admin guard --enforce'],
            ],
            'check' => 'centinela-admin guard --show',
            'risk'  => 'Un acceso correcto desde fuera de la politica nunca se banea, solo avisa: no puedes '
                     . 'dejarte fuera a ti mismo. Aun asi, --enforce se niega a activarse si algun acceso tuyo '
                     . 'del historico quedaria fuera.',
        ]
        : [
            'why'   => 'La valla esta en marcha. Estos son los mandos del dia a dia; cualquier cambio se '
                     . 'aplica en la siguiente pasada del vigilante (menos de un minuto).',
            'steps' => [
                ['do' => 'Vas a entrar desde un sitio nuevo (viaje, otra conexion): anade el rango antes o cuando llegue el aviso',
                 'cmd' => 'centinela-admin guard --allow-ip IP/32'],
                ['do' => 'Permitir o retirar un pais',
                 'cmd' => 'centinela-admin guard --allow-country PT'],
                ['do' => 'Quitar un rango que ya no uses',
                 'cmd' => 'centinela-admin guard --deny-ip IP/32'],
                ['do' => 'Ver que haria la politica actual contra el historico',
                 'cmd' => 'centinela-admin guard --simulate'],
                ['do' => 'Apagarla (los baneos ya hechos siguen en fail2ban)',
                 'cmd' => 'centinela-admin guard --disable'],
            ],
            'check' => 'centinela-admin guard --show',
        ];
    if (empty($g['enabled'])): ?>
      <p class="muted" style="margin:0 0 4px;">Sin politica de origen para los servicios de administracion.</p>
      <?= ui_guide($guiaValla, 'Como se configura') ?>
    <?php else: ?>
      <dl class="kv">
        <dt>Estado</dt>
        <dd><?php if (($g['action'] ?? '') === 'observe'): ?>
          <span style="color:var(--warning)">observacion</span>
        <?php else: ?>
          <span style="color:var(--good)">activa</span>
        <?php endif; ?></dd>
        <dt>Protege</dt><dd><?= h(implode(', ', (array) ($g['services'] ?? []))) ?></dd>
        <dt>Paises</dt><dd><?= h(implode(', ', (array) ($g['allow_countries'] ?? [])) ?: '—') ?></dd>
        <dt>Rangos</dt><dd class="mono" style="font-size:11.5px;"><?= h(implode(' ', (array) ($g['allow_ips'] ?? [])) ?: '—') ?></dd>
        <?php if (($g['action'] ?? '') === 'observe'): ?>
          <dt>Banearia</dt><dd><?= nfmt($g['would_ban'] ?? 0) ?> IP(s)</dd>
        <?php else: ?>
          <dt>Baneos hoy</dt><dd<?= ($g['banned_today'] ?? 0) > 0 ? ' style="color:var(--warning);font-weight:600"' : '' ?>><?= nfmt($g['banned_today'] ?? 0) ?></dd>
        <?php endif; ?>
        <?php if (!empty($g['pending_geo'])): ?>
          <dt>Sin pais aun</dt><dd class="muted"><?= nfmt($g['pending_geo']) ?> IP(s)</dd>
        <?php endif; ?>
      </dl>
      <?php if (!empty($g['out_logins'])): ?>
        <div class="alert err" style="margin:10px 0 0;font-size:12.5px;"><span aria-hidden="true">▲</span>
        <span><?= count($g['out_logins']) ?> acceso(s) correcto(s) desde fuera de la politica en 24h.</span></div>
      <?php endif; ?>
      <?= ui_guide($guiaValla, 'Como se gestiona') ?>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2>Syslog remoto</h2>
    <?php
    // La configuracion del syslog vive en config.php, que esta web ya carga.
    $sl = $CFG['syslog'] ?? [];
    $slOn = !empty($sl['enabled']) && !empty($sl['server']);
    $guiaSyslog = [
        'why'   => 'Exporta la salud, los ataques y las transiciones de incidencias a un SIEM o syslog '
                 . 'centralizado, en RFC 5424 con el cuerpo en clave=valor: rsyslog, syslog-ng, Graylog o '
                 . 'Wazuh lo parten sin configurar nada. Solo salen resumenes y transiciones, nunca el '
                 . 'inventario completo del servidor.',
        'steps' => [
            ['do' => 'Apunta la exportacion a tu servidor (udp o tcp; el puerto tipico es el 514)',
             'cmd' => 'centinela-admin syslog --server siem.midominio.com:514 udp'],
            ['do' => 'Manda un mensaje de prueba y comprueba que llega al otro lado',
             'cmd' => 'centinela-admin syslog --test'],
            ['do' => 'Sube el umbral si solo quieres avisos e incidencias graves',
             'cmd' => 'centinela-admin syslog --min-sev warn'],
            ['do' => 'En el receptor, filtra por el tag «centinela». Llegan tres tipos: event=health '
                   . '(nota y recuentos, cada recogida), event=attacks (resumen de actividad) y '
                   . 'event=finding con state=new, changed o resolved (solo transiciones, para alertar '
                   . 'sobre lo que aparece y no sobre lo que sigue).'],
            ['do' => 'Para dejar de exportar', 'cmd' => 'centinela-admin syslog --disable'],
        ],
        'check' => 'centinela-admin syslog --show',
        'risk'  => 'Con UDP el envio no confirma la entrega: tras configurarlo, verifica en el receptor. '
                 . 'Un fallo de red nunca afecta a la recogida; el error queda en el journal del colector.',
    ];
    if (!$slOn): ?>
      <p class="muted" style="margin:0 0 4px;">Sin exportar: el estado solo se ve en este panel.</p>
    <?php else: ?>
      <dl class="kv">
        <dt>Estado</dt><dd><span style="color:var(--good)">exportando</span></dd>
        <dt>Servidor</dt><dd class="mono" style="font-size:11.5px;"><?= h((string) $sl['server']) ?></dd>
        <dt>Protocolo</dt><dd><?= h(strtolower((string) ($sl['proto'] ?? 'udp'))) ?></dd>
        <dt>Umbral</dt><dd><?= h((string) ($sl['min_sev'] ?? 'info')) ?></dd>
      </dl>
    <?php endif; ?>
    <?= ui_guide($guiaSyslog, $slOn ? 'Como se gestiona' : 'Como se configura') ?>
  </div>

  <div class="card">
    <h2>Cortafuegos y SSH</h2>
    <?php $fw = $st['firewall'] ?? []; $ssh = $st['ssh'] ?? []; ?>
    <dl class="kv">
      <dt>Cortafuegos</dt><dd><?= h($fw['backend'] ?? 'ninguno') ?></dd>
      <dt>Politica INPUT</dt>
      <dd><?php $pol = strtoupper((string) ($fw['default_input'] ?? '')); ?>
        <span style="color:<?= $pol === 'DROP' ? 'var(--good)' : 'var(--warning)' ?>"><?= h($pol ?: '—') ?></span></dd>
      <dt>Reglas</dt><dd><?= nfmt($fw['rules'] ?? 0) ?></dd>
      <?php if (!empty($ssh['available'])): ?>
      <dt>Puerto SSH</dt><dd class="mono"><?= h(implode(', ', $ssh['ports'] ?? [])) ?></dd>
      <dt>Root por SSH</dt>
      <dd><span style="color:<?= ($ssh['permit_root_login'] ?? '') === 'yes' ? 'var(--critical)' : 'var(--good)' ?>">
        <?= h($ssh['permit_root_login'] ?? '—') ?></span></dd>
      <dt>Contrase&ntilde;a</dt>
      <dd><span style="color:<?= !empty($ssh['password_auth']) ? 'var(--warning)' : 'var(--good)' ?>">
        <?= !empty($ssh['password_auth']) ? 'permitida' : 'deshabilitada' ?></span></dd>
      <?php endif; ?>
    </dl>
  </div>

  <div class="card">
    <h2>Productos de seguridad</h2>
    <?php $pr = $st['secprod']['products'] ?? []; ?>
    <dl class="kv">
      <dt>ModSecurity</dt>
      <dd><?php $ms = $pr['modsecurity'] ?? [];
        if (!empty($ms['enabled'])) echo '<span style="color:var(--good)">activo</span>';
        elseif (!empty($ms['installed'])) echo '<span style="color:var(--warning)">instalado, inactivo</span>';
        else echo '<span class="muted">no instalado</span>'; ?></dd>
      <dt>Imunify</dt>
      <dd><?php $im = $pr['imunify'] ?? [];
        if (!empty($im['active'])) echo '<span style="color:var(--good)">activo</span>';
        elseif (!empty($im['installed'])) echo '<span style="color:var(--warning)">instalado, parado</span>';
        else echo '<span class="muted">no instalado</span>'; ?></dd>
      <dt>Antivirus</dt>
      <dd><?php $so = $pr['sophos'] ?? [];
        if (!empty($so['active'])) echo '<span style="color:var(--good)">activo</span>';
        elseif (!empty($so['installed'])) echo '<span style="color:var(--warning)">instalado, parado</span>';
        else echo '<span class="muted">no instalado</span>'; ?></dd>
      <?php if (!empty($st['plesk']['installed'])): ?>
      <dt>Plesk</dt>
      <dd><?= h($st['plesk']['version'] ?? '') ?>
        <?php if (!empty($st['plesk']['upgrade'])): ?>
          <br><span style="color:var(--warning);font-size:12px;">→ <?= h($st['plesk']['upgrade']['version']) ?></span>
        <?php endif; ?></dd>
      <?php elseif (!empty($st['panel']['version'])): ?>
      <dt><?= h($st['panel']['label'] ?? 'Panel') ?></dt>
      <dd><?= h($st['panel']['version']) ?>
        <?php if (!empty($st['panel']['updates'])): ?>
          <br><span style="color:var(--warning);font-size:12px;">→ actualizacion disponible</span>
        <?php endif; ?></dd>
      <?php elseif (!empty($st['panel']['label'])): ?>
      <dt>Plataforma</dt>
      <dd><?= h($st['panel']['label']) ?></dd>
      <?php endif; ?>
    </dl>
  </div>
</div>

<!-- ========================================================= SISTEMA === -->
<h2 class="section-title">Sistema</h2>
<div class="grid cols-3">
  <div class="card">
    <h2>Recursos</h2>
    <dl class="kv">
      <dt>Kernel</dt><dd class="mono" style="font-size:12px;"><?= h($sys['kernel']['running'] ?? '') ?></dd>
      <?php if (!empty($sys['needs_reboot'])): ?>
      <dt>Pendiente</dt><dd><span style="color:var(--critical)"><?= h($sys['kernel']['installed'] ?? '') ?></span></dd>
      <?php endif; ?>
      <dt>Carga</dt><dd><?= h(str_replace('.', ',', (string) ($sys['load']['1'] ?? 0))) ?>
        <span class="muted">/ <?= (int) ($sys['cpu_cores'] ?? 1) ?> nucleos</span></dd>
      <?php $mem = $sys['memory'] ?? []; if (!empty($mem['total'])): ?>
      <dt>Memoria</dt><dd><?= h(ui_bytes((float) ($mem['total'] - $mem['available']))) ?>
        <span class="muted">de <?= h(ui_bytes((float) $mem['total'])) ?></span></dd>
      <?php endif; ?>
      <?php foreach (($sys['disks'] ?? []) as $d): ?>
      <dt>Disco <?= h($d['mount']) ?></dt>
      <dd><span style="color:<?= $d['percent'] >= 85 ? 'var(--critical)' : ($d['percent'] >= 75 ? 'var(--warning)' : 'inherit') ?>">
        <?= (int) $d['percent'] ?>%</span> <span class="muted"><?= h(ui_bytes((float) $d['free'])) ?> libres</span></dd>
      <?php endforeach; ?>
    </dl>
  </div>

  <div class="card">
    <h2>Servicios</h2>
    <div class="scroll-x"><table class="data">
      <tbody>
      <?php foreach (($st['services']['services'] ?? []) as $s):
        $up = $s['active'] === 'active'; ?>
        <tr>
          <td class="mono"><?= h($s['unit']) ?></td>
          <td style="text-align:right">
            <span class="tag <?= $up ? 'ok' : 'crit' ?>">
              <span aria-hidden="true"><?= $up ? '✓' : '✕' ?></span> <?= h($s['active']) ?></span>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table></div>
  </div>

  <div class="card">
    <h2>Certificados</h2>
    <div class="scroll-x"><table class="data">
      <thead><tr><th>Dominio</th><th class="num">Caduca</th></tr></thead>
      <tbody>
      <?php foreach (array_slice($st['certs']['certificates'] ?? [], 0, 12) as $c):
        $col = $c['days_left'] < 0 ? 'var(--critical)' : ($c['days_left'] <= 14 ? 'var(--warning)' : 'var(--good)'); ?>
        <tr>
          <td style="overflow-wrap:anywhere;"><?= h($c['cn']) ?></td>
          <td class="num nowrap" style="color:<?= $col ?>">
            <?= $c['days_left'] < 0 ? 'caducado' : (int) $c['days_left'] . ' d' ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (empty($st['certs']['certificates'])): ?>
        <tr><td colspan="2" class="empty">Sin certificados detectados.</td></tr>
      <?php endif; ?>
      </tbody>
    </table></div>
  </div>
</div>

<div class="grid cols-2" style="margin-top:var(--gap);">
  <div class="card">
    <h2>Puertos expuestos a la red</h2>
    <div class="scroll-x"><table class="data">
      <thead><tr><th>Puerto</th><th>Proto</th><th>Direccion</th><th>Proceso</th></tr></thead>
      <tbody>
      <?php foreach (array_filter($st['ports']['ports'] ?? [], fn($p) => $p['public']) as $p): ?>
        <tr>
          <td class="mono"><?= (int) $p['port'] ?></td>
          <td class="muted"><?= h($p['proto']) ?></td>
          <td class="mono muted" style="font-size:12px;overflow-wrap:anywhere;"><?= h($p['address']) ?></td>
          <td><?= h($p['process']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table></div>
  </div>

  <div class="card">
    <h2>Accesos al panel</h2>
    <div class="scroll-x"><table class="data">
      <thead><tr><th>Fecha</th><th>Evento</th><th>IP</th></tr></thead>
      <tbody>
      <?php foreach (recent_access_log(12) as $l):
        $bad = str_contains($l['event'], 'fail') || str_contains($l['event'], 'denied') || str_contains($l['event'], 'lockout'); ?>
        <tr>
          <td class="muted nowrap"><?= h(date('d/m H:i', strtotime($l['time']))) ?></td>
          <td><span class="tag <?= $bad ? 'crit' : 'ok' ?>">
            <span aria-hidden="true"><?= $bad ? '✕' : '✓' ?></span> <?= h($l['event']) ?></span></td>
          <td class="mono"><?= h($l['ip']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table></div>
  </div>
</div>

<p class="lg-note" style="margin-top:28px;text-align:center;">
  Centinela v<?= h(CENT_VERSION) ?> · recogida en <?= (int) ($st['collect_ms'] ?? 0) ?> ms ·
  el panel solo lee datos; no ejecuta acciones sobre el servidor.
</p>

</div>

<div class="tooltip" id="tt" role="status" aria-live="polite"></div>
<script src="<?= asset('assets/app.js') ?>"></script>
</body>
</html>
