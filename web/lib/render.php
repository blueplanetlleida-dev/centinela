<?php
/**
 * Centinela - componentes de presentacion.
 *
 * Las graficas se generan como SVG en el servidor: no hace falta ninguna
 * libreria de terceros, lo que encaja con la politica de contenido estricta.
 */

declare(strict_types=1);

/** Colores por severidad, coherentes con la hoja de estilos. */
function ui_sev_color(string $sev): string
{
    return ['crit' => '#d03b3b', 'warn' => '#fab219', 'info' => '#3987e5', 'ok' => '#0ca30c'][$sev] ?? '#898781';
}

/** Icono textual por severidad: el color nunca viaja solo. */
function ui_sev_icon(string $sev): string
{
    return ['crit' => '✕', 'warn' => '!', 'info' => 'i', 'ok' => '✓'][$sev] ?? '·';
}

function ui_sev_label(string $sev): string
{
    return ['crit' => 'Critico', 'warn' => 'Aviso', 'info' => 'Info', 'ok' => 'Correcto'][$sev] ?? $sev;
}

/** Color de la nota global segun el tramo. */
function ui_score_color(int $s): string
{
    if ($s >= 90) return '#0ca30c';
    if ($s >= 70) return '#fab219';
    return '#d03b3b';
}

/** Numero formateado al estilo espanol. */
function nfmt($n): string
{
    return number_format((float) $n, 0, ',', '.');
}

/** Bandera emoji desde el codigo ISO de pais. */
function ui_flag(?string $cc): string
{
    if (!$cc || strlen($cc) !== 2 || !ctype_alpha($cc)) {
        return '🏳';
    }
    $cc = strtoupper($cc);
    return mb_chr(0x1F1E6 + ord($cc[0]) - 65, 'UTF-8') . mb_chr(0x1F1E6 + ord($cc[1]) - 65, 'UTF-8');
}

/** Duracion legible. */
function ui_duration(int $sec): string
{
    if ($sec < 60)    return $sec . ' s';
    if ($sec < 3600)  return intdiv($sec, 60) . ' min';
    if ($sec < 86400) return intdiv($sec, 3600) . ' h ' . intdiv($sec % 3600, 60) . ' min';
    $d = intdiv($sec, 86400);
    return $d . ' d ' . intdiv($sec % 86400, 3600) . ' h';
}

/** Fecha relativa breve. */
function ui_ago(?int $ts): string
{
    if (!$ts) {
        return '—';
    }
    $d = time() - $ts;
    if ($d < 0)     return date('d/m H:i', $ts);
    if ($d < 60)    return 'hace ' . $d . ' s';
    if ($d < 3600)  return 'hace ' . intdiv($d, 60) . ' min';
    if ($d < 86400) return 'hace ' . intdiv($d, 3600) . ' h';
    return 'hace ' . intdiv($d, 86400) . ' d';
}

/** Bytes legibles. */
function ui_bytes(float $b): string
{
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; }
    return str_replace('.', ',', (string) round($b, $b < 10 && $i > 0 ? 1 : 0)) . ' ' . $u[$i];
}

/**
 * Medidor circular de la nota global.
 * El valor va tambien como texto: el arco no es el unico canal.
 */
function ui_gauge(int $score, string $grade): string
{
    $c   = ui_score_color($score);
    $r   = 56;
    $circ = 2 * M_PI * $r;
    $dash = $circ * ($score / 100);
    $rest = $circ - $dash;

    return '<div class="gauge">'
        . '<svg width="132" height="132" viewBox="0 0 132 132" role="img" aria-label="Nota de salud: ' . $score . ' sobre 100">'
        . '<circle cx="66" cy="66" r="' . $r . '" fill="none" stroke="#2c2c2a" stroke-width="11"/>'
        . '<circle cx="66" cy="66" r="' . $r . '" fill="none" stroke="' . $c . '" stroke-width="11"'
        . ' stroke-linecap="round" stroke-dasharray="' . round($dash, 2) . ' ' . round($rest, 2) . '"/>'
        . '</svg>'
        . '<div class="val"><div class="num" style="color:' . $c . '">' . $score . '</div>'
        . '<div class="lbl">' . h($grade) . '</div></div></div>';
}

/**
 * Grafico de barras verticales para una serie temporal.
 * Serie unica: un solo color, sin degradado por valor (el largo ya codifica
 * la magnitud; tenirlo ademas seria doble codificacion).
 *
 * @param array $data  [['label'=>..., 'value'=>int, 'tip'=>string], ...]
 */
function ui_bars(array $data, int $height = 120, int $labelEvery = 1): string
{
    if (!$data) {
        return '<div class="empty">Sin datos en el periodo.</div>';
    }

    $n    = count($data);
    $max  = max(1, max(array_column($data, 'value')));
    $padB = 18;                       // espacio para las etiquetas del eje
    $plot = $height - $padB;
    $gap  = 2;                        // separacion entre barras
    $w    = 1000;                     // ancho virtual; el SVG escala al contenedor
    $bw   = max(1.0, ($w - ($n - 1) * $gap) / $n);

    $bars = '';
    $labels = '';
    // Lineas de referencia al 50% y 100% del maximo
    $grid = '';
    foreach ([0.5, 1.0] as $frac) {
        $y = round($plot - $plot * $frac, 1);
        $grid .= '<line class="gridline" x1="0" y1="' . $y . '" x2="' . $w . '" y2="' . $y . '"/>';
    }

    foreach ($data as $i => $d) {
        $v  = (int) $d['value'];
        $bh = $v > 0 ? max(2.0, ($v / $max) * $plot) : 0.0;
        $x  = round($i * ($bw + $gap), 2);
        $y  = round($plot - $bh, 2);

        if ($bh > 0) {
            $bars .= '<rect class="bar" x="' . $x . '" y="' . $y . '" width="' . round($bw, 2) . '"'
                . ' height="' . round($bh, 2) . '" rx="2"'
                . ' data-tip="' . h($d['tip'] ?? ($d['label'] . ': ' . nfmt($v))) . '"></rect>';
        } else {
            // Marca minima para que el hueco siga siendo interactivo
            $bars .= '<rect class="bar" x="' . $x . '" y="' . ($plot - 1) . '" width="' . round($bw, 2) . '"'
                . ' height="1" opacity="0.25" data-tip="' . h($d['tip'] ?? ($d['label'] . ': 0')) . '"></rect>';
        }

        if ($labelEvery > 0 && $i % $labelEvery === 0) {
            $labels .= '<text class="axis-label" x="' . round($x + $bw / 2, 2) . '" y="' . ($plot + 13)
                . '" text-anchor="middle">' . h($d['label']) . '</text>';
        }
    }

    $baseline = '<line class="baseline" x1="0" y1="' . $plot . '" x2="' . $w . '" y2="' . $plot . '"/>';

    return '<svg class="chart" viewBox="0 0 ' . $w . ' ' . $height . '" preserveAspectRatio="none"'
        . ' height="' . $height . '" role="img" aria-label="Serie temporal de intentos fallidos">'
        . $grid . $bars . $baseline . '</svg>'
        . '<svg class="chart" viewBox="0 0 ' . $w . ' 16" height="16" style="margin-top:-16px" preserveAspectRatio="none" aria-hidden="true">'
        . $labels . '</svg>';
}

/** Linea de tendencia simple para el historico de la nota. */
function ui_sparkline(array $points, int $w = 220, int $h = 40): string
{
    $vals = array_column($points, 's');
    if (count($vals) < 2) {
        return '';
    }
    $min = min($vals);
    $max = max($vals);
    $range = max(1, $max - $min);
    $n = count($vals);

    $coords = [];
    foreach ($vals as $i => $v) {
        $x = round(($i / ($n - 1)) * $w, 2);
        $y = round($h - (($v - $min) / $range) * ($h - 4) - 2, 2);
        $coords[] = $x . ',' . $y;
    }

    return '<svg class="chart" width="' . $w . '" height="' . $h . '" viewBox="0 0 ' . $w . ' ' . $h . '"'
        . ' role="img" aria-label="Tendencia de la nota: de ' . $vals[0] . ' a ' . end($vals) . '">'
        . '<polyline points="' . implode(' ', $coords) . '" fill="none" stroke="#3987e5" stroke-width="2"'
        . ' stroke-linejoin="round" stroke-linecap="round"/></svg>';
}

/** Barra horizontal dentro de una celda de tabla. */
function ui_inline_bar(int $value, int $max): string
{
    $pct = $max > 0 ? min(100, ($value / $max) * 100) : 0;
    return '<div class="bar-cell"><div class="fill" style="width:' . round($pct, 1) . '%"></div>'
        . '<span>' . nfmt($value) . '</span></div>';
}

/** Bloque de comando con boton de copiar. */
function ui_cmd(string $cmd): string
{
    if ($cmd === '') {
        return '';
    }
    return '<div class="cmd"><code>' . h($cmd) . '</code>'
        . '<button type="button" class="copy" data-cmd="' . h($cmd) . '"'
        . ' title="Copiar al portapapeles">Copiar</button></div>';
}

/**
 * Guia de solucion desplegable.
 *
 * Va cerrada por defecto: la tarjeta tiene que seguir leyendose de un vistazo.
 */
function ui_guide(array $g, string $summary = 'Guia de solucion'): string
{
    if (!$g) {
        return '';
    }
    $out = '<details class="guide"><summary>' . h($summary) . '</summary><div class="guide-body">';

    if (!empty($g['why'])) {
        $out .= '<p class="why">' . h($g['why']) . '</p>';
    }
    if (!empty($g['risk'])) {
        $out .= '<p class="risk"><span aria-hidden="true">▲</span> <strong>Antes de tocar nada:</strong> '
            . h($g['risk']) . '</p>';
    }
    if (!empty($g['steps'])) {
        $out .= '<ol class="steps">';
        foreach ($g['steps'] as $st) {
            $out .= '<li><span class="do">' . h($st['do'] ?? '') . '</span>'
                . ui_cmd((string) ($st['cmd'] ?? '')) . '</li>';
        }
        $out .= '</ol>';
    }
    if (!empty($g['check'])) {
        $out .= '<p class="check-label">Queda resuelto cuando esto responde lo esperado:</p>'
            . ui_cmd((string) $g['check']);
    }
    if (!empty($g['docs'])) {
        $out .= '<p class="docs"><a href="' . h($g['docs']) . '" target="_blank" rel="noopener noreferrer">'
            . 'Documentacion oficial</a></p>';
    }
    return $out . '</div></details>';
}

/**
 * Celda de estado de una IP atacante: si algun jail la retiene y el boton
 * para cambiarlo.
 *
 * El boton no ejecuta nada: encola la peticion y el ejecutor privilegiado
 * decide. Aqui solo se pinta el estado que dejo la ultima recogida.
 */
function ui_ban_cell(array $ip, bool $f2bActivo): string
{
    $dir   = (string) ($ip['ip'] ?? '');
    $jails = (array) ($ip['banned_in'] ?? []);

    if (!$f2bActivo) {
        return '<span class="muted">sin fail2ban</span>';
    }

    if ($jails) {
        $donde = implode(', ', array_map('h', array_slice($jails, 0, 2)));
        return '<span class="tag ok" title="Bloqueada en ' . $donde . '">'
             . '<span aria-hidden="true">✓</span> Bloqueada</span>'
             . '<button type="button" class="ipact" data-act="unban" data-ip="' . h($dir) . '">Desbloquear</button>';
    }

    return '<span class="tag warn"><span aria-hidden="true">!</span> Suelta</span>'
         . '<button type="button" class="ipact" data-act="ban" data-ip="' . h($dir) . '">Bloquear</button>';
}

/** Tarjeta de incidencia. */
function ui_finding(array $f): string
{
    $c   = ui_sev_color($f['sev']);
    $id  = (string) ($f['id'] ?? '');
    $out = '<div class="finding" data-fid="' . h($id) . '">'
        . '<div class="bar" style="background:' . $c . '"></div><div class="body">'
        . '<div class="title"><span class="tag ' . h($f['sev']) . '">'
        . '<span aria-hidden="true">' . ui_sev_icon($f['sev']) . '</span> ' . ui_sev_label($f['sev'])
        . '</span> <span class="what">' . h($f['title']) . '</span>'
        // El boton no comprueba nada por si mismo: pide al colector que
        // vuelva a medir y luego mira si este hallazgo sigue en la lista.
        . '<button type="button" class="recheck" data-fid="' . h($id) . '">Volver a comprobar</button>'
        . '</div>';
    if (!empty($f['detail'])) {
        $out .= '<div class="detail">' . h($f['detail']) . '</div>';
    }
    if (!empty($f['fix'])) {
        $out .= '<div class="fix">' . h($f['fix']) . '</div>';
    }
    $out .= ui_guide((array) ($f['guide'] ?? []));
    $out .= '<div class="verdict" hidden></div>';
    return $out . '</div></div>';
}
