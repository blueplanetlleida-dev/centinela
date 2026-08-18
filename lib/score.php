<?php
/**
 * Centinela - motor de puntuacion de salud.
 *
 * Parte de 100 y resta el peso de cada hallazgo, con rendimientos
 * decrecientes por categoria: diez avisos del mismo tipo no deben hundir
 * la nota igual que diez problemas distintos.
 */

declare(strict_types=1);

function compute_score(array $findings): array
{
    $byCategory = [];
    foreach ($findings as $f) {
        $cat = explode('.', $f['id'])[0];
        $byCategory[$cat][] = $f;
    }

    $penalty = 0.0;
    foreach ($byCategory as $cat => $list) {
        // Ordenamos por gravedad para que el peor pese completo
        usort($list, fn($a, $b) => sev_weight($b['sev']) <=> sev_weight($a['sev']));
        $factor = 1.0;
        foreach ($list as $f) {
            $penalty += sev_weight($f['sev']) * $factor;
            $factor *= 0.5;   // el segundo hallazgo de la categoria pesa la mitad, etc.
        }
    }

    $score = (int) max(0, min(100, round(100 - $penalty)));

    $counts = ['crit' => 0, 'warn' => 0, 'info' => 0, 'ok' => 0];
    foreach ($findings as $f) {
        $counts[$f['sev']] = ($counts[$f['sev']] ?? 0) + 1;
    }

    if ($counts['crit'] > 0) {
        $grade = $score >= 70 ? 'atencion' : 'critico';
    } elseif ($counts['warn'] > 2) {
        $grade = 'mejorable';
    } elseif ($counts['warn'] > 0) {
        $grade = 'bueno';
    } else {
        $grade = 'excelente';
    }

    // Orden de presentacion: criticos primero, luego avisos, luego informativos
    $order = ['crit' => 0, 'warn' => 1, 'info' => 2, 'ok' => 3];
    usort($findings, fn($a, $b) => [$order[$a['sev']] ?? 9, $a['id']] <=> [$order[$b['sev']] ?? 9, $b['id']]);

    return [
        'score'    => $score,
        'grade'    => $grade,
        'counts'   => $counts,
        'findings' => array_values($findings),
    ];
}
