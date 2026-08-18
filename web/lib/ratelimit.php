<?php
/**
 * Centinela - limitacion de frecuencia basada en ficheros.
 *
 * No requiere Redis ni base de datos: cada cubo es un fichero con marcas
 * de tiempo. Suficiente para el volumen de un panel de un solo servidor.
 */

declare(strict_types=1);

/** Directorio donde viven los cubos. */
function rl_dir(): string
{
    global $CFG;
    $d = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/rl';
    if (!is_dir($d)) {
        @mkdir($d, 0770, true);
    }
    return $d;
}

/**
 * Consume una unidad del cubo $key. Devuelve false si se supero el limite.
 *
 * @param string $key    Identificador (accion + IP, normalmente).
 * @param int    $limit  Numero de eventos permitidos en la ventana.
 * @param int    $window Ventana en segundos.
 */
function rl_hit(string $key, int $limit, int $window): bool
{
    $file = rl_dir() . '/' . hash('sha256', $key) . '.rl';
    $now  = time();

    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        // Si no podemos escribir, no bloqueamos el servicio.
        return true;
    }
    flock($fh, LOCK_EX);

    $raw   = stream_get_contents($fh) ?: '';
    $stamps = array_values(array_filter(
        array_map('intval', explode(',', $raw)),
        fn($t) => $t > $now - $window
    ));

    $allowed = count($stamps) < $limit;
    if ($allowed) {
        $stamps[] = $now;
    }

    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, implode(',', array_slice($stamps, -1000)));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);

    return $allowed;
}

/** Cuantos eventos quedan en la ventana sin consumir ninguno. */
function rl_remaining(string $key, int $limit, int $window): int
{
    $file = rl_dir() . '/' . hash('sha256', $key) . '.rl';
    if (!is_readable($file)) {
        return $limit;
    }
    $now = time();
    $stamps = array_filter(array_map('intval', explode(',', (string) file_get_contents($file))),
        fn($t) => $t > $now - $window);
    return max(0, $limit - count($stamps));
}

/** Limpia cubos antiguos; lo llama el colector de vez en cuando. */
function rl_gc(int $olderThan = 86400): void
{
    foreach (glob(rl_dir() . '/*.rl') ?: [] as $f) {
        if (@filemtime($f) < time() - $olderThan) {
            @unlink($f);
        }
    }
}
