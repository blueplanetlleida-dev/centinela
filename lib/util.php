<?php
/**
 * Centinela - utilidades compartidas.
 *
 * Este fichero lo carga UNICAMENTE el colector, que corre como root.
 * La capa web nunca lo incluye: la web solo lee JSON ya generado.
 */

declare(strict_types=1);

const CENT_VERSION = '1.1.2';

/**
 * Ejecuta un comando sin shell. Todos los argumentos van en array, asi que
 * no hay interpolacion ni posibilidad de inyeccion.
 *
 * @return array{out:string, err:string, code:int, ok:bool}
 */
function run(array $cmd, int $timeout = 15, ?string $stdin = null): array
{
    $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $env  = ['PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL' => 'C'];

    $proc = @proc_open($cmd, $desc, $pipes, null, $env);
    if (!is_resource($proc)) {
        return ['out' => '', 'err' => 'no se pudo lanzar el proceso', 'code' => 127, 'ok' => false];
    }

    if ($stdin !== null) {
        fwrite($pipes[0], $stdin);
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $out = $err = '';
    $deadline = microtime(true) + $timeout;

    while (true) {
        $out .= stream_get_contents($pipes[1]);
        $err .= stream_get_contents($pipes[2]);

        $st = proc_get_status($proc);
        if (!$st['running']) {
            break;
        }
        if (microtime(true) > $deadline) {
            proc_terminate($proc, SIGKILL);
            $out .= stream_get_contents($pipes[1]);
            $err .= "\n[centinela] timeout tras {$timeout}s";
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
            return ['out' => trim($out), 'err' => trim($err), 'code' => 124, 'ok' => false];
        }
        usleep(20000);
    }

    $out .= stream_get_contents($pipes[1]);
    $err .= stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);

    return ['out' => trim($out), 'err' => trim($err), 'code' => $code, 'ok' => $code === 0];
}

/** Atajo: solo la salida estandar, cadena vacia si falla. */
function run_out(array $cmd, int $timeout = 15): string
{
    return run($cmd, $timeout)['out'];
}

/**
 * Ejecuta una tuberia de shell. SOLO para cadenas literales del propio
 * colector: nunca debe recibir nada derivado de entrada de usuario.
 */
function sh(string $pipeline, int $timeout = 20): string
{
    return run(['/bin/bash', '-o', 'pipefail', '-c', $pipeline], $timeout)['out'];
}

/** ¿Existe el binario en el PATH? */
function have(string $bin): bool
{
    static $cache = [];
    if (!isset($cache[$bin])) {
        $cache[$bin] = run(['/usr/bin/which', $bin], 5)['ok'];
    }
    return $cache[$bin];
}

/** Lee un fichero devolviendo null si no existe o no se puede leer. */
function slurp(string $path, int $maxBytes = 2097152): ?string
{
    if (!is_readable($path)) {
        return null;
    }
    $data = @file_get_contents($path, false, null, 0, $maxBytes);
    return $data === false ? null : $data;
}

/** Primera captura de un patron sobre un texto, o null. */
function match1(string $pattern, ?string $subject): ?string
{
    if ($subject === null) {
        return null;
    }
    return preg_match($pattern, $subject, $m) ? $m[1] : null;
}

/** Convierte "1.2.3" en un entero comparable. */
function vnum(string $v): int
{
    $p = array_map('intval', array_pad(explode('.', preg_replace('/[^0-9.]/', '', $v)), 4, 0));
    return $p[0] * 1000000000 + $p[1] * 1000000 + $p[2] * 1000 + $p[3];
}

/** Escritura atomica: se escribe a temporal y se renombra. */
function write_atomic(string $path, string $data, int $mode = 0640, ?string $group = null): bool
{
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
        return false;
    }
    $tmp = $path . '.tmp' . getmypid();
    if (@file_put_contents($tmp, $data, LOCK_EX) === false) {
        return false;
    }
    @chmod($tmp, $mode);
    if ($group !== null) {
        @chgrp($tmp, $group);
    }
    return @rename($tmp, $path);
}

/** Severidades ordenadas. */
const SEV_OK   = 'ok';
const SEV_INFO = 'info';
const SEV_WARN = 'warn';
const SEV_CRIT = 'crit';

/** Peso de cada severidad para el calculo del score. */
function sev_weight(string $sev): int
{
    return ['ok' => 0, 'info' => 0, 'warn' => 6, 'crit' => 18][$sev] ?? 0;
}

/**
 * Construye un hallazgo normalizado.
 * Todo modulo devuelve una lista de estos.
 *
 * El campo 'fix' es la accion en una linea, pensada para el correo y para la
 * vista rapida. La guia, cuando existe, es la version larga que el panel
 * despliega: por que importa, pasos con su comando y como verificarlo.
 */
function finding(string $id, string $sev, string $title, string $detail = '', string $fix = '', array $guide = []): array
{
    return [
        'id'     => $id,
        'sev'    => $sev,
        'title'  => $title,
        'detail' => $detail,
        'fix'    => $fix,
        'guide'  => $guide,
    ];
}

/**
 * Construye la guia de solucion de un hallazgo.
 *
 * @param string $why   Por que importa, en una o dos frases.
 * @param array  $steps Pasos en orden. Cada uno es una cadena (solo texto) o
 *                      ['do' => texto, 'cmd' => comando a ejecutar].
 * @param string $check Comando que confirma que ha quedado resuelto.
 * @param string $risk  Aviso cuando el cambio puede dejar sin acceso o cortar
 *                      un servicio. Se muestra destacado antes de los pasos.
 * @param string $docs  Enlace a documentacion oficial.
 */
function guide(string $why, array $steps, string $check = '', string $risk = '', string $docs = ''): array
{
    $norm = [];
    foreach ($steps as $s) {
        if (is_string($s)) {
            $s = ['do' => $s];
        }
        $do = trim((string) ($s['do'] ?? ''));
        if ($do === '') {
            continue;
        }
        $norm[] = ['do' => $do, 'cmd' => trim((string) ($s['cmd'] ?? ''))];
    }

    $g = ['why' => trim($why), 'steps' => $norm, 'check' => trim($check),
          'risk' => trim($risk), 'docs' => trim($docs)];

    // Fuera lo vacio: el JSON de estado se sirve entero al navegador.
    return array_filter($g, fn($v) => $v !== '' && $v !== []);
}

/** Formatea bytes a unidades legibles. */
function human_bytes(float $b): string
{
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($b >= 1024 && $i < count($u) - 1) {
        $b /= 1024;
        $i++;
    }
    return round($b, $b < 10 && $i > 0 ? 1 : 0) . ' ' . $u[$i];
}

/** Log del colector a stderr, visible en journalctl. */
function clog(string $msg): void
{
    fwrite(STDERR, '[centinela] ' . $msg . "\n");
}

/** Directorio de estado; lo fija el colector al arrancar. */
function state_dir(?string $set = null): string
{
    static $dir = '/var/lib/centinela';
    if ($set !== null) {
        $dir = rtrim($set, '/');
    }
    return $dir;
}

/**
 * Ignora la cache de modulos durante esta ejecucion.
 *
 * Lo activa «centinela-collect --fresh», que es como el panel recomprueba una
 * incidencia: sin esto, modulos caros como el correo o los certificados
 * devolverian el valor guardado y la recomprobacion no reflejaria el arreglo
 * que el administrador acaba de hacer.
 */
function cache_bypass(?bool $set = null): bool
{
    static $on = false;
    if ($set !== null) {
        $on = $set;
    }
    return $on;
}

/**
 * Cachea el resultado de una operacion cara (consulta de red, apt update...)
 * durante $ttl segundos. Si la operacion falla se conserva el valor anterior,
 * de modo que un fallo puntual de red no vacia el panel.
 */
function cached(string $key, int $ttl, callable $fn, bool $externo = false)
{
    $file = state_dir() . '/cache/' . preg_replace('/[^a-z0-9_.-]/i', '_', $key) . '.json';
    $now  = time();

    // Lo marcado como externo se conserva incluso en una recomprobacion: son
    // datos de fuera (catalogos de versiones, consultas al fabricante) que no
    // cambian porque el administrador acabe de arreglar algo aqui, y volver a
    // pedirlos por red multiplica por diez lo que tarda la recogida.
    if ((!cache_bypass() || $externo) && is_file($file)) {
        $prev = json_decode((string) slurp($file), true);
        if (is_array($prev) && isset($prev['at'], $prev['val']) && ($now - $prev['at']) < $ttl) {
            return $prev['val'];
        }
    } else {
        $prev = null;
    }

    try {
        $val = $fn();
    } catch (Throwable $e) {
        clog("cache {$key}: fallo ({$e->getMessage()}), se conserva valor previo");
        return $prev['val'] ?? null;
    }

    write_atomic($file, json_encode(['at' => $now, 'val' => $val], JSON_UNESCAPED_SLASHES), 0640);
    return $val;
}
