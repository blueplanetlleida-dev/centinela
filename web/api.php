<?php
/**
 * Centinela - API del panel.
 *
 * Requiere sesion. En GET solo sirve el estado que dejo el colector. En POST
 * nada se ejecuta aqui: toda accion acaba siendo un fichero en la cola que
 * recoge un servicio de systemd corriendo como root.
 *
 * Con las correcciones («fix») el reparto de responsabilidades es el mismo que
 * con los bloqueos: aqui solo se comprueba que la clave tenga forma de clave.
 * Que esa clave exista, que se pueda aplicar en este servidor y que comandos
 * implica lo decide el catalogo del lado privilegiado, que es el unico que lo
 * sabe. Esta capa no puede ampliar la lista ni aunque la comprometan.
 */

declare(strict_types=1);
require __DIR__ . '/lib/boot.php';
require __DIR__ . '/lib/auth.php';

send_security_headers();
header('Cache-Control: no-store');

if (!ip_allowed()) {
    json_out(['error' => 'origen no permitido'], 403);
}
if (!is_authenticated()) {
    json_out(['error' => 'no autenticado'], 401);
}

// ------------------------------------------------------------------ POST ---
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    if (!csrf_check($_POST['csrf'] ?? null)) {
        json_out(['error' => 'token de sesion invalido, recarga la pagina'], 403);
    }
    $accion = (string) ($_POST['action'] ?? '');
    if (!in_array($accion, ['recheck', 'ban', 'unban', 'fix'], true)) {
        json_out(['error' => 'accion desconocida'], 400);
    }

    // ------------------------------------------ aplicar una correccion ---
    if ($accion === 'fix') {
        $yo = client_ip();
        // Mas estricto que con los bloqueos: una correccion toca el servidor,
        // no una tabla de iptables, y nadie necesita lanzar diez por minuto.
        if (!rl_hit('fix:m:' . $yo, 3, 60) || !rl_hit('fix:h:' . $yo, 15, 3600)) {
            json_out(['error' => 'demasiadas correcciones seguidas, espera un momento'], 429);
        }

        $clave = strtolower(trim((string) ($_POST['fix'] ?? '')));
        if (!preg_match('/^[a-z0-9._-]{1,32}$/', $clave)) {
            json_out(['error' => 'la correccion pedida no es valida'], 400);
        }

        $id   = bin2hex(random_bytes(8));
        $ruta = action_queue_path($id);
        if ($ruta === '') {
            json_out(['error' => 'la cola de acciones no esta disponible; revisa los permisos'], 503);
        }

        $peticion = [
            'id'     => $id,
            'at'     => time(),
            'action' => 'fix',
            'fix'    => $clave,
            'user'   => (string) ($_SESSION['uid'] ?? ''),
            'origin' => $yo,
        ];
        if (@file_put_contents($ruta, json_encode($peticion, JSON_UNESCAPED_SLASHES), LOCK_EX) === false) {
            json_out(['error' => 'no se pudo encolar la correccion'], 503);
        }
        @chmod($ruta, 0660);

        auth_log('fix', (string) ($_SESSION['uid'] ?? ''), $clave);
        // 'since' deja al panel la marca de tiempo previa, para que luego pueda
        // distinguir la recogida nueva (la que dispara el propio arreglo) de la
        // que ya estaba en pantalla.
        $st = read_state();
        json_out(['queued' => true, 'id' => $id, 'since' => (int) ($st['generated_at'] ?? 0)]);
    }

    // ------------------------------------------- bloquear / desbloquear ---
    if ($accion === 'ban' || $accion === 'unban') {
        $yo = client_ip();
        if (!rl_hit('act:m:' . $yo, 10, 60) || !rl_hit('act:h:' . $yo, 60, 3600)) {
            json_out(['error' => 'demasiadas acciones seguidas, espera un momento'], 429);
        }

        $objetivo = trim((string) ($_POST['ip'] ?? ''));
        if (!filter_var($objetivo, FILTER_VALIDATE_IP)) {
            json_out(['error' => 'la direccion no es valida'], 400);
        }
        // Primera red de seguridad, la de verdad esta en el ejecutor: aqui se
        // evita el error mas facil de cometer, bloquearse uno mismo.
        if ($accion === 'ban' && $objetivo === $yo) {
            json_out(['error' => 'esa es la direccion desde la que estas conectado'], 400);
        }

        $id   = bin2hex(random_bytes(8));
        $ruta = action_queue_path($id);
        if ($ruta === '') {
            json_out(['error' => 'la cola de acciones no esta disponible; revisa los permisos'], 503);
        }

        $peticion = [
            'id'     => $id,
            'at'     => time(),
            'action' => $accion,
            'ip'     => $objetivo,
            'user'   => (string) ($_SESSION['uid'] ?? ''),
            'origin' => $yo,
        ];
        if ($accion === 'ban' && !empty($_POST['jail'])) {
            $jail = (string) $_POST['jail'];
            if (preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $jail)) {
                $peticion['jail'] = $jail;
            }
        }

        if (@file_put_contents($ruta, json_encode($peticion, JSON_UNESCAPED_SLASHES), LOCK_EX) === false) {
            json_out(['error' => 'no se pudo encolar la accion'], 503);
        }
        @chmod($ruta, 0660);

        auth_log($accion, (string) ($_SESSION['uid'] ?? ''), $objetivo);
        json_out(['queued' => true, 'id' => $id]);
    }

    // ------------------------------------------------------ recomprobar ---
    // Cada recomprobacion arranca una recogida completa como root. Se limita
    // para que nadie con sesion abierta pueda encadenarlas indefinidamente.
    $ip = client_ip();
    if (!rl_hit('recheck:m:' . $ip, 6, 60) || !rl_hit('recheck:h:' . $ip, 40, 3600)) {
        json_out(['error' => 'demasiadas recomprobaciones seguidas, espera un momento'], 429);
    }

    $st    = read_state();
    $since = (int) ($st['generated_at'] ?? 0);
    $req   = queue_path('recheck.req');

    // Si ya hay una peticion sin atender, no se pisa: el resultado sera el mismo.
    if (is_file($req) && (time() - (int) @filemtime($req)) < 300) {
        json_out(['queued' => true, 'already' => true, 'since' => $since]);
    }

    // El contenido es solo traza: quien lo pidio y cuando. El servicio de
    // systemd no lo interpreta, siempre ejecuta la misma orden.
    $body = json_encode([
        'at'   => time(),
        'user' => (string) ($_SESSION['uid'] ?? ''),
        'ip'   => $ip,
    ], JSON_UNESCAPED_SLASHES);

    if ($req === '' || @file_put_contents($req, $body, LOCK_EX) === false) {
        json_out(['error' => 'no se pudo encolar la recomprobacion; revisa los permisos de la cola'], 503);
    }
    @chmod($req, 0660);

    auth_log('recheck', (string) ($_SESSION['uid'] ?? ''), 'recogida forzada desde el panel');
    json_out(['queued' => true, 'since' => $since]);
}

// ------------------------------------------------------------------- GET ---
$st = read_state();
if ($st === null) {
    json_out(['error' => 'sin datos del colector'], 503);
}

switch ((string) ($_GET['v'] ?? 'all')) {
    // Solo la marca de tiempo: lo que consulta el refresco automatico.
    case 'stamp':
        json_out([
            'generated_at' => (int) ($st['generated_at'] ?? 0),
            'score'        => (int) ($st['health']['score'] ?? 0),
            'crit'         => (int) ($st['health']['counts']['crit'] ?? 0),
            // Hay una recomprobacion pedida y todavia sin atender.
            'pending'      => is_file(queue_path('recheck.req')),
        ]);

    // Resultado de una accion concreta: lo que sondea el panel tras pulsar.
    case 'action':
        $id = (string) ($_GET['id'] ?? '');
        if (!preg_match('/^[a-f0-9]{8,32}$/', $id)) {
            json_out(['error' => 'identificador no valido'], 400);
        }
        foreach (array_reverse(read_actions()) as $a) {
            if (($a['id'] ?? '') === $id) {
                json_out(['done' => true, 'result' => $a]);
            }
        }
        json_out(['done' => false]);

    // Progreso de una correccion larga: lo que sondea el panel mientras apt
    // trabaja. Se devuelve solo la cola del registro; el resto ya se ha visto.
    case 'job':
        $job = read_job((string) ($_GET['id'] ?? ''));
        if ($job === null) {
            json_out(['error' => 'no hay ningun trabajo con ese identificador'], 404);
        }
        $job['log'] = array_slice((array) ($job['log'] ?? []), -40);
        json_out($job);

    case 'health':
        json_out($st['health'] ?? []);

    case 'attacks':
        json_out($st['attacks'] ?? []);

    case 'system':
        json_out($st['system'] ?? []);

    case 'all':
    default:
        json_out($st);
}
