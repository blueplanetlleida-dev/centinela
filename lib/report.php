<?php
/**
 * Centinela - composicion de los correos.
 *
 * HTML pensado para clientes de correo: tablas, estilos en linea y cero
 * recursos externos. Nada de flexbox ni grid, que Outlook no renderiza.
 */

declare(strict_types=1);

/** Escapa para HTML. Acepta cualquier escalar por comodidad de las plantillas. */
function esc($s): string
{
    if (is_array($s) || is_object($s)) {
        $s = '';
    }
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Color asociado a cada severidad. */
function sev_color(string $sev): string
{
    return [
        'crit' => '#b42318',
        'warn' => '#b54708',
        'info' => '#175cd3',
        'ok'   => '#027a48',
    ][$sev] ?? '#475467';
}

function sev_bg(string $sev): string
{
    return [
        'crit' => '#fef3f2',
        'warn' => '#fffaeb',
        'info' => '#eff8ff',
        'ok'   => '#ecfdf3',
    ][$sev] ?? '#f9fafb';
}

function sev_label(string $sev): string
{
    return ['crit' => 'CRITICO', 'warn' => 'AVISO', 'info' => 'INFO', 'ok' => 'OK'][$sev] ?? strtoupper($sev);
}

/** Color de la nota global. */
function score_color(int $s): string
{
    if ($s >= 90) return '#027a48';
    if ($s >= 75) return '#4ca30d';
    if ($s >= 50) return '#b54708';
    return '#b42318';
}

/** Bandera emoji a partir del codigo de pais ISO. */
function cc_flag(?string $cc): string
{
    if (!$cc || strlen($cc) !== 2 || !ctype_alpha($cc)) {
        return '';
    }
    $cc = strtoupper($cc);
    return mb_chr(0x1F1E6 + ord($cc[0]) - 65, 'UTF-8') . mb_chr(0x1F1E6 + ord($cc[1]) - 65, 'UTF-8');
}

/** Duracion legible en espanol. */
function human_uptime(int $sec): string
{
    $d = intdiv($sec, 86400);
    $h = intdiv($sec % 86400, 3600);
    $m = intdiv($sec % 3600, 60);
    if ($d > 0) return "{$d} d {$h} h";
    if ($h > 0) return "{$h} h {$m} min";
    return "{$m} min";
}

/** Envoltorio HTML comun de los correos. */
function mail_wrapper(string $title, string $preheader, string $inner, string $footerNote = ''): string
{
    $t   = esc($title);
    $p   = esc($preheader);
    $ver = CENT_VERSION;
    return <<<HTML
<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{$t}</title></head>
<body style="margin:0;padding:0;background:#f2f4f7;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">{$p}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f4f7;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;box-shadow:0 1px 3px rgba(16,24,40,.1);">
{$inner}
<tr><td style="padding:18px 28px 26px;border-top:1px solid #eaecf0;color:#667085;font-size:12px;line-height:1.6;">
{$footerNote}
Generado por <strong>Centinela</strong> v{$ver} &middot; este mensaje es automatico.
</td></tr>
</table>
</td></tr></table>
</body></html>
HTML;
}

/** Cabecera con la nota global. */
function block_header(string $title, string $subtitle, int $score, string $grade): string
{
    $c = score_color($score);
    $t = esc($title);
    $s = esc($subtitle);
    $g = esc(ucfirst($grade));
    return <<<HTML
<tr><td style="padding:28px 28px 20px;background:{$c};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
    <td style="vertical-align:middle;">
      <div style="color:rgba(255,255,255,.85);font-size:13px;letter-spacing:.4px;text-transform:uppercase;">Centinela</div>
      <div style="color:#fff;font-size:22px;font-weight:700;padding-top:4px;">{$t}</div>
      <div style="color:rgba(255,255,255,.9);font-size:13px;padding-top:6px;">{$s}</div>
    </td>
    <td align="right" style="vertical-align:middle;width:110px;">
      <div style="background:rgba(255,255,255,.16);border-radius:10px;padding:12px 8px;text-align:center;">
        <div style="color:#fff;font-size:34px;font-weight:800;line-height:1;">{$score}</div>
        <div style="color:rgba(255,255,255,.9);font-size:11px;padding-top:4px;text-transform:uppercase;letter-spacing:.5px;">{$g}</div>
      </div>
    </td>
  </tr></table>
</td></tr>
HTML;
}

/** Fila de metricas en tarjetas. */
function block_metrics(array $metrics): string
{
    $cells = '';
    $n = max(1, count($metrics));
    $w = (int) floor(100 / $n);
    foreach ($metrics as $m) {
        $label = esc($m['label']);
        $value = esc((string) $m['value']);
        $color = $m['color'] ?? '#101828';
        $sub   = isset($m['sub']) ? '<div style="color:#667085;font-size:11px;padding-top:3px;">' . esc($m['sub']) . '</div>' : '';
        $cells .= <<<HTML
<td width="{$w}%" style="padding:14px 10px;text-align:center;border-right:1px solid #eaecf0;">
  <div style="color:{$color};font-size:20px;font-weight:700;line-height:1.1;">{$value}</div>
  <div style="color:#475467;font-size:11px;padding-top:5px;text-transform:uppercase;letter-spacing:.3px;">{$label}</div>
  {$sub}
</td>
HTML;
    }
    return '<tr><td style="padding:0 20px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eaecf0;border-radius:10px;margin-top:18px;">'
        . '<tr>' . $cells . '</tr></table></td></tr>';
}

/** Titulo de seccion. */
function block_section(string $title): string
{
    return '<tr><td style="padding:26px 28px 8px;"><div style="font-size:15px;font-weight:700;color:#101828;border-bottom:2px solid #eaecf0;padding-bottom:8px;">'
        . esc($title) . '</div></td></tr>';
}

/** Lista de hallazgos. */
function block_findings(array $findings, int $limit = 20): string
{
    if (!$findings) {
        return '<tr><td style="padding:6px 28px 4px;"><div style="background:#ecfdf3;border-radius:8px;padding:14px;color:#027a48;font-size:13px;">Sin incidencias abiertas. Todas las comprobaciones han pasado.</div></td></tr>';
    }
    $rows = '';
    foreach (array_slice($findings, 0, $limit) as $f) {
        $c   = sev_color($f['sev']);
        $bg  = sev_bg($f['sev']);
        $lbl = sev_label($f['sev']);
        $fix = $f['fix'] !== ''
            ? '<div style="padding-top:7px;font-size:12px;color:#475467;">Accion: <code style="background:#f2f4f7;padding:2px 5px;border-radius:4px;font-size:11px;">' . esc($f['fix']) . '</code></div>'
            : '';
        $detail = $f['detail'] !== ''
            ? '<div style="padding-top:4px;font-size:13px;color:#475467;line-height:1.5;">' . esc($f['detail']) . '</div>'
            : '';
        $rows .= <<<HTML
<tr><td style="padding:0 28px 10px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{$bg};border-left:3px solid {$c};border-radius:6px;">
  <tr><td style="padding:12px 14px;">
    <span style="display:inline-block;background:{$c};color:#fff;font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;letter-spacing:.5px;">{$lbl}</span>
    <span style="font-size:14px;font-weight:600;color:#101828;padding-left:8px;">
HTML;
        $rows .= esc($f['title']) . '</span>' . $detail . $fix . '</td></tr></table></td></tr>';
    }
    if (count($findings) > $limit) {
        $rows .= '<tr><td style="padding:2px 28px 8px;color:#667085;font-size:12px;">y ' . (count($findings) - $limit) . ' incidencia(s) mas en el panel.</td></tr>';
    }
    return $rows;
}

/** Tabla generica. */
function block_table(array $headers, array $rows, string $emptyMsg = 'Sin datos.'): string
{
    if (!$rows) {
        return '<tr><td style="padding:4px 28px 8px;color:#667085;font-size:13px;">' . esc($emptyMsg) . '</td></tr>';
    }
    $th = '';
    foreach ($headers as $h) {
        $align = $h[1] ?? 'left';
        $th .= '<th style="text-align:' . $align . ';padding:8px 10px;font-size:11px;color:#475467;text-transform:uppercase;letter-spacing:.3px;border-bottom:1px solid #eaecf0;font-weight:600;">' . esc($h[0]) . '</th>';
    }
    $tr = '';
    foreach ($rows as $row) {
        $tds = '';
        foreach ($row as $i => $cell) {
            $align = $headers[$i][1] ?? 'left';
            $tds .= '<td style="text-align:' . $align . ';padding:9px 10px;font-size:13px;color:#101828;border-bottom:1px solid #f2f4f7;">' . $cell . '</td>';
        }
        $tr .= '<tr>' . $tds . '</tr>';
    }
    return '<tr><td style="padding:4px 28px 10px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">'
        . '<tr>' . $th . '</tr>' . $tr . '</table></td></tr>';
}

/** Grafico de barras en HTML puro para la serie diaria. */
function block_sparkbars(array $series, string $caption = ''): string
{
    if (!$series) {
        return '';
    }
    $max = max(1, max(array_column($series, 'count')));
    $bars = '';
    $w = (int) floor(100 / max(1, count($series)));
    foreach ($series as $s) {
        $h = (int) max(2, round(($s['count'] / $max) * 54));
        $color = $s['count'] >= $max * 0.75 ? '#b42318' : ($s['count'] >= $max * 0.4 ? '#f79009' : '#7cd4fd');
        $day = esc(date('d/m', strtotime($s['date'])));
        $bars .= '<td width="' . $w . '%" style="vertical-align:bottom;padding:0 1px;text-align:center;">'
            . '<div style="background:' . $color . ';height:' . $h . 'px;border-radius:2px 2px 0 0;" title="' . $s['count'] . '"></div>'
            . '<div style="font-size:9px;color:#98a2b3;padding-top:3px;">' . $day . '</div></td>';
    }
    $cap = $caption ? '<div style="font-size:12px;color:#667085;padding-bottom:8px;">' . esc($caption) . '</div>' : '';
    return '<tr><td style="padding:6px 28px 12px;">' . $cap
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="height:70px;"><tr>' . $bars . '</tr></table></td></tr>';
}

// ---------------------------------------------------------------------------
// Informe semanal
// ---------------------------------------------------------------------------

/**
 * Compone el informe semanal completo.
 *
 * @return array{subject:string, html:string, text:string}
 */
function render_weekly_report(array $st): array
{
    $host    = $st['system']['hostname'] ?? php_uname('n');
    $health  = $st['health'] ?? ['score' => 0, 'grade' => '?', 'counts' => [], 'findings' => []];
    $atk     = $st['attacks'] ?? [];
    $score   = (int) ($health['score'] ?? 0);
    $desde   = date('d/m/Y', time() - 7 * 86400);
    $hasta   = date('d/m/Y');

    // Comparativa semana actual frente a la anterior
    $series = $atk['series_daily'] ?? [];
    $thisW = $prevW = 0;
    $nd = count($series);
    for ($i = 0; $i < $nd; $i++) {
        if ($i >= $nd - 7) { $thisW += $series[$i]['count']; }
        else               { $prevW += $series[$i]['count']; }
    }
    $delta = $prevW > 0 ? round((($thisW - $prevW) / $prevW) * 100) : null;
    $deltaTxt = $delta === null ? 'sin comparativa' : ($delta >= 0 ? "+{$delta}% vs semana previa" : "{$delta}% vs semana previa");

    $inner  = block_header(
        'Informe semanal de seguridad',
        $host . ' · ' . $desde . ' a ' . $hasta,
        $score,
        (string) ($health['grade'] ?? '')
    );

    $counts = $health['counts'] ?? [];
    $inner .= block_metrics([
        ['label' => 'Criticos', 'value' => $counts['crit'] ?? 0, 'color' => ($counts['crit'] ?? 0) > 0 ? '#b42318' : '#027a48'],
        ['label' => 'Avisos',   'value' => $counts['warn'] ?? 0, 'color' => ($counts['warn'] ?? 0) > 0 ? '#b54708' : '#027a48'],
        ['label' => 'Ataques',  'value' => number_format($thisW, 0, ',', '.'), 'sub' => $deltaTxt],
        ['label' => 'IPs unicas', 'value' => $atk['unique_ips_7d'] ?? 0],
    ]);

    // Estado general
    $sys = $st['system'] ?? [];
    $inner .= block_section('Estado del sistema');
    $rows = [];
    $rows[] = ['Sistema operativo', esc($sys['os'] ?? '?')];
    $rows[] = ['Kernel', esc($sys['kernel']['running'] ?? '?')
        . (($sys['needs_reboot'] ?? false) ? ' <span style="color:#b42318;font-weight:600;">(reinicio pendiente)</span>' : '')];
    $rows[] = ['Tiempo encendido', esc(human_uptime((int) ($sys['uptime_sec'] ?? 0)))];
    if (!empty($st['plesk']['installed'])) {
        $pl = $st['plesk'];
        $rows[] = ['Plesk', esc($pl['version'] ?? '?')
            . (!empty($pl['upgrade']) ? ' <span style="color:#b54708;font-weight:600;">→ ' . esc($pl['upgrade']['version']) . ' disponible</span>' : ' <span style="color:#027a48;">(al dia)</span>')];
    }
    if (!empty($st['panel']['version']) && ($st['panel']['platform'] ?? '') !== 'plesk') {
        $pn = $st['panel'];
        $rows[] = [esc($pn['label'] ?? 'Panel'), esc($pn['version'])
            . (!empty($pn['updates']) ? ' <span style="color:#b54708;font-weight:600;">→ actualizacion disponible</span>' : ' <span style="color:#027a48;">(al dia)</span>')];
    }
    $upd = $st['updates'] ?? [];
    $rows[] = ['Actualizaciones', ((int) ($upd['total'] ?? 0)) . ' pendientes'
        . (($upd['security'] ?? 0) > 0 ? ' <span style="color:#b42318;font-weight:600;">(' . $upd['security'] . ' de seguridad)</span>' : '')];
    foreach (($sys['disks'] ?? []) as $d) {
        $col = $d['percent'] >= 85 ? '#b42318' : '#101828';
        $rows[] = ['Disco ' . esc($d['mount']), '<span style="color:' . $col . '">' . $d['percent'] . '% usado · ' . esc(human_bytes((float) $d['free'])) . ' libres</span>'];
    }
    $inner .= block_table([['Elemento'], ['Valor']], $rows);

    // Incidencias
    $inner .= block_section('Incidencias abiertas');
    $inner .= block_findings($health['findings'] ?? [], 12);

    // Ataques
    $inner .= block_section('Actividad de ataques');
    $inner .= block_sparkbars($series, 'Intentos de autenticacion fallidos por dia');

    $ipRows = [];
    foreach (array_slice($atk['top_ips'] ?? [], 0, 10) as $ip) {
        $flag = cc_flag($ip['cc'] ?? null);
        $org  = $ip['org'] ? esc(mb_strimwidth((string) $ip['org'], 0, 38, '…')) : '<span style="color:#98a2b3">desconocido</span>';
        $ipRows[] = [
            '<code style="font-size:12px;">' . esc($ip['ip']) . '</code>',
            $flag . ' ' . esc($ip['cc'] ?? '?'),
            $org,
            '<strong>' . number_format((int) $ip['count'], 0, ',', '.') . '</strong>',
        ];
    }
    $inner .= block_table([['IP'], ['Pais'], ['Operador'], ['Intentos', 'right']], $ipRows, 'Sin ataques registrados esta semana.');

    // Usuarios objetivo
    $userRows = [];
    foreach (array_slice($atk['top_users'] ?? [], 0, 8) as $u) {
        $userRows[] = ['<code style="font-size:12px;">' . esc($u['user']) . '</code>',
            '<strong>' . number_format((int) $u['count'], 0, ',', '.') . '</strong>'];
    }
    if ($userRows) {
        $inner .= block_section('Usuarios mas probados');
        $inner .= block_table([['Usuario'], ['Intentos', 'right']], $userRows);
    }

    // Accesos correctos
    $succ = $atk['successes'] ?? [];
    if ($succ) {
        $inner .= block_section('Accesos correctos recientes');
        $sr = [];
        foreach (array_slice($succ, 0, 8) as $s) {
            $sr[] = [
                esc(date('d/m H:i', $s['ts'])),
                '<code style="font-size:12px;">' . esc($s['ip']) . '</code>',
                esc($s['user']),
                esc($s['method']),
            ];
        }
        $inner .= block_table([['Fecha'], ['IP'], ['Usuario'], ['Metodo']], $sr);
    }

    // Certificados
    $certs = array_slice($st['certs']['certificates'] ?? [], 0, 6);
    if ($certs) {
        $inner .= block_section('Certificados');
        $cr = [];
        foreach ($certs as $c) {
            $col = $c['days_left'] < 0 ? '#b42318' : ($c['days_left'] <= 14 ? '#b54708' : '#027a48');
            $txt = $c['days_left'] < 0 ? 'caducado' : $c['days_left'] . ' dias';
            $cr[] = [esc($c['cn']), '<span style="color:' . $col . ';font-weight:600;">' . $txt . '</span>', esc(date('d/m/Y', $c['valid_to']))];
        }
        $inner .= block_table([['Certificado'], ['Restante'], ['Caduca']], $cr);
    }

    $html = mail_wrapper(
        "Informe semanal · {$host}",
        "Salud {$score}/100 · " . ($counts['crit'] ?? 0) . ' criticos · ' . number_format($thisW, 0, ',', '.') . ' ataques',
        $inner,
        'Recibes este informe porque figuras como administrador del servidor <strong>' . esc($host) . '</strong>.<br>'
    );

    $text = render_weekly_text($st, $thisW, $deltaTxt);

    $subject = sprintf('[Centinela] %s · salud %d/100 · %s',
        $host, $score, ($counts['crit'] ?? 0) > 0 ? ($counts['crit'] . ' critico(s)') : 'sin criticos');

    return ['subject' => $subject, 'html' => $html, 'text' => $text];
}

/** Version en texto plano del informe semanal. */
function render_weekly_text(array $st, int $weekAttacks, string $deltaTxt): string
{
    $host   = $st['system']['hostname'] ?? '?';
    $health = $st['health'] ?? [];
    $atk    = $st['attacks'] ?? [];
    $l = [];
    $l[] = 'CENTINELA - INFORME SEMANAL DE SEGURIDAD';
    $l[] = str_repeat('=', 55);
    $l[] = "Servidor: {$host}";
    $l[] = 'Periodo:  ' . date('d/m/Y', time() - 7 * 86400) . ' a ' . date('d/m/Y');
    $l[] = '';
    $l[] = 'SALUD GLOBAL: ' . ($health['score'] ?? '?') . '/100 (' . ($health['grade'] ?? '?') . ')';
    $l[] = '  Criticos: ' . ($health['counts']['crit'] ?? 0) . '   Avisos: ' . ($health['counts']['warn'] ?? 0);
    $l[] = '';
    $l[] = 'SISTEMA';
    $l[] = '  SO:     ' . ($st['system']['os'] ?? '?');
    $l[] = '  Kernel: ' . ($st['system']['kernel']['running'] ?? '?') . (($st['system']['needs_reboot'] ?? false) ? '  [REINICIO PENDIENTE]' : '');
    $l[] = '  Uptime: ' . human_uptime((int) ($st['system']['uptime_sec'] ?? 0));
    if (!empty($st['plesk']['installed'])) {
        $l[] = '  Plesk:  ' . ($st['plesk']['version'] ?? '?') . (!empty($st['plesk']['upgrade']) ? '  -> ' . $st['plesk']['upgrade']['version'] . ' disponible' : '  (al dia)');
    }
    if (!empty($st['panel']['version']) && ($st['panel']['platform'] ?? '') !== 'plesk') {
        $l[] = '  ' . str_pad(($st['panel']['label'] ?? 'Panel') . ':', 8) . $st['panel']['version'] . (!empty($st['panel']['updates']) ? '  -> actualizacion disponible' : '  (al dia)');
    }
    $l[] = '  Paquetes pendientes: ' . ($st['updates']['total'] ?? 0) . ' (' . ($st['updates']['security'] ?? 0) . ' de seguridad)';
    $l[] = '';
    $l[] = 'INCIDENCIAS ABIERTAS';
    if (empty($health['findings'])) {
        $l[] = '  Ninguna.';
    } else {
        foreach (array_slice($health['findings'], 0, 15) as $f) {
            $l[] = '  [' . sev_label($f['sev']) . '] ' . $f['title'];
            if ($f['detail'] !== '') { $l[] = '        ' . $f['detail']; }
            if ($f['fix'] !== '')    { $l[] = '        Accion: ' . $f['fix']; }
        }
    }
    $l[] = '';
    $l[] = 'ATAQUES (7 dias)';
    $l[] = '  Intentos fallidos: ' . number_format($weekAttacks, 0, ',', '.') . ' (' . $deltaTxt . ')';
    $l[] = '  IPs unicas:        ' . ($atk['unique_ips_7d'] ?? 0);
    $l[] = '';
    $l[] = '  Top origenes:';
    foreach (array_slice($atk['top_ips'] ?? [], 0, 8) as $ip) {
        $l[] = sprintf('    %-16s %-3s %-32s %6d', $ip['ip'], $ip['cc'] ?? '?', mb_strimwidth((string) ($ip['org'] ?? '-'), 0, 32, '..'), $ip['count']);
    }
    $l[] = '';
    $l[] = '  Usuarios mas probados:';
    foreach (array_slice($atk['top_users'] ?? [], 0, 8) as $u) {
        $l[] = sprintf('    %-24s %6d', $u['user'], $u['count']);
    }
    $l[] = '';
    $l[] = str_repeat('-', 55);
    $l[] = 'Generado por Centinela v' . CENT_VERSION . ' - mensaje automatico.';
    return implode("\n", $l);
}

// ---------------------------------------------------------------------------
// Alertas
// ---------------------------------------------------------------------------

/** Compone una alerta por incidencias nuevas. */
function render_alert(array $st, array $newFindings, array $resolved = []): array
{
    $host   = $st['system']['hostname'] ?? php_uname('n');
    $health = $st['health'] ?? [];
    $score  = (int) ($health['score'] ?? 0);
    $crit   = array_filter($newFindings, fn($f) => $f['sev'] === 'crit');

    $inner  = block_header(
        $crit ? 'Alerta de seguridad' : 'Cambio en el estado de seguridad',
        $host . ' · ' . date('d/m/Y H:i'),
        $score,
        (string) ($health['grade'] ?? '')
    );

    $inner .= block_section(count($newFindings) . ' incidencia(s) nueva(s)');
    $inner .= block_findings($newFindings, 15);

    if ($resolved) {
        $inner .= block_section('Resueltas desde el ultimo aviso');
        $rows = [];
        foreach (array_slice($resolved, 0, 10) as $r) {
            $rows[] = ['<span style="color:#027a48;">&#10003;</span> ' . esc($r['title'])];
        }
        $inner .= block_table([['Incidencia']], $rows);
    }

    $html = mail_wrapper(
        "Alerta · {$host}",
        count($newFindings) . ' incidencia(s) nueva(s) en ' . $host,
        $inner
    );

    $l = ['CENTINELA - ALERTA DE SEGURIDAD', str_repeat('=', 45), "Servidor: {$host}", 'Fecha: ' . date('d/m/Y H:i'),
          'Salud: ' . $score . '/100', '', 'INCIDENCIAS NUEVAS:'];
    foreach ($newFindings as $f) {
        $l[] = '  [' . sev_label($f['sev']) . '] ' . $f['title'];
        if ($f['detail'] !== '') { $l[] = '        ' . $f['detail']; }
        if ($f['fix'] !== '')    { $l[] = '        Accion: ' . $f['fix']; }
    }
    if ($resolved) {
        $l[] = '';
        $l[] = 'RESUELTAS:';
        foreach ($resolved as $r) { $l[] = '  [OK] ' . $r['title']; }
    }

    $subject = sprintf('[Centinela] %s %s · %d incidencia(s) nueva(s)',
        $crit ? 'CRITICO' : 'Aviso', $host, count($newFindings));

    return ['subject' => $subject, 'html' => $html, 'text' => implode("\n", $l), 'priority' => (bool) $crit];
}
