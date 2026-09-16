<?php
/**
 * Centinela - catalogo de correcciones aplicables desde el panel.
 *
 * Reglas que sostienen la seguridad de este fichero, las mismas que rigen el
 * looking glass:
 *   1. La lista es cerrada. Quien pulsa el boton elige una clave, nunca un
 *      comando: lo que llega desde la web es 'f2b.reload', no una cadena que
 *      alguien vaya a ejecutar.
 *   2. Nunca se invoca un shell. Cada paso es un array de argumentos que va
 *      directo a proc_open, asi que no hay nada que escapar ni que citar.
 *   3. El catalogo vive aqui, en lib/, del lado privilegiado. La capa web solo
 *      conoce la clave y la etiqueta; no puede ampliar ni alterar la lista.
 *
 * Por que NO se ejecuta directamente el 'cmd' de la guia del hallazgo, que
 * seria lo comodo: esos comandos estan escritos para que los lea una persona.
 * Muchos llevan marcadores como NOMBRE, DOMINIO o RANGO que un humano
 * sustituye al copiarlos, y ejecutarlos tal cual haria cosas absurdas o
 * peligrosas. Otros son de diagnostico, no de arreglo. Y alguno, como vaciar
 * la cola de correo, seria activamente daNino si la causa resulta ser una
 * cuenta comprometida enviando spam. De ahi que cada correccion se escriba a
 * mano, una a una, y se decida si merece un boton.
 *
 * Que entra en esta primera tanda: solo lo idempotente, rapido y sin corte de
 * servicio. Repetir cualquiera de estas acciones dos veces no hace daNo, todas
 * terminan en segundos y ninguna deja una web o un buzon sin responder.
 *
 * Que se ha dejado fuera a proposito:
 *   - Lo que tarda minutos (apt-get upgrade): el ejecutor tiene un TTL de 300 s
 *     y la unidad de systemd un TimeoutStartSec de 120. Necesita un modelo de
 *     trabajo largo con estado y sondeo, no este de pedir y esperar.
 *   - Lo que borra datos (journalctl --vacuum-time): libera disco, pero se
 *     lleva por delante registros que quiza hagan falta para investigar.
 *   - Lo que puede dejarte fuera del servidor (PasswordAuthentication no).
 *     Ese no deberia tener boton nunca, ni con confirmacion.
 *   - El reinicio: se lleva por delante el propio panel y necesita su propio
 *     flujo, con aviso y espera hasta que la maquina vuelve.
 */

declare(strict_types=1);

/**
 * Comprueba que una unidad de systemd existe de verdad en esta maquina.
 *
 * Hace falta porque el nombre del servicio cambia segun como se instalara el
 * producto: el antivirus de Plesk es 'plesk-sophos-av' aqui y 'sav-protect' en
 * otras instalaciones. Preguntar antes evita ofrecer un boton que solo puede
 * fallar.
 */
function fix_unit_exists(string $unit): bool
{
    $r = run(['/usr/bin/systemctl', 'list-unit-files', '--no-legend', $unit], 10);
    return $r['ok'] && trim($r['out']) !== '';
}

/** Primera unidad de la lista que exista, o null si no hay ninguna. */
function fix_first_unit(array $units): ?string
{
    foreach ($units as $u) {
        if (fix_unit_exists($u)) {
            return $u;
        }
    }
    return null;
}

/**
 * Catalogo de correcciones.
 *
 * Cada entrada:
 *   'applies'   ids de hallazgo que resuelve.
 *   'label'     texto del boton.
 *   'desc'      lo que se va a hacer, en una frase. Se enseNa antes de
 *               confirmar, asi que tiene que decir la verdad completa.
 *   'available' opcional: si devuelve false, no se ofrece el boton. Se evalua
 *               en la recogida, que corre como root.
 *   'steps'     devuelve la lista de comandos (arrays de argumentos) en orden.
 *               Si alguno falla, se para y se informa.
 *   'check'     comando que confirma el resultado, y 'expect' lo que deberia
 *               responder. Se ejecuta despues del arreglo: asi el panel puede
 *               decir «hecho y comprobado» en vez de «orden enviada».
 *   'timeout'   segundos por comando.
 */
function fix_catalog(): array
{
    return [
        // ------------------------------------------------------ fail2ban ---
        'f2b.start' => [
            'applies' => ['f2b.down'],
            'label'   => 'Arrancar fail2ban',
            'desc'    => 'Habilita el servicio para que arranque solo y lo pone en marcha ahora. '
                       . 'Los jails vuelven a filtrar; no afecta a ningun otro servicio.',
            'steps'   => fn() => [['/usr/bin/systemctl', 'enable', '--now', 'fail2ban']],
            'check'   => fn() => ['/usr/bin/systemctl', 'is-active', 'fail2ban'],
            'expect'  => '/^active$/m',
            'timeout' => 45,
        ],

        'f2b.reload' => [
            'applies' => ['f2b.nojails'],
            'label'   => 'Recargar los jails',
            'desc'    => 'Relee la configuracion de fail2ban sin reiniciarlo. Los bloqueos en vigor '
                       . 'se mantienen. Si algun jail estaba mal escrito, seguira sin cargar: el '
                       . 'resultado te dira que dijo fail2ban.',
            // -t primero: si la configuracion no es valida, es preferible
            // enterarse antes de pedirle a fail2ban que la cargue.
            'steps'   => fn() => [
                ['/usr/bin/fail2ban-client', '-t'],
                ['/usr/bin/fail2ban-client', 'reload'],
            ],
            'check'   => fn() => ['/usr/bin/fail2ban-client', 'status'],
            'expect'  => '/Jail list:\s*\S/',
            'timeout' => 60,
        ],

        // ----------------------------------------------------- antivirus ---
        'sophos.start' => [
            'applies'   => ['sec.sophos'],
            'label'     => 'Arrancar el antivirus',
            'desc'      => 'Habilita y arranca el servicio de Sophos, y activa el temporizador que '
                         . 'descarga las firmas. Ojo: esto pone el motor a funcionar, pero no mete '
                         . 'el correo por el antivirus; esa parte se activa desde el panel de Plesk.',
            'available' => fn() => fix_first_unit(['plesk-sophos-av.service', 'sav-protect.service']) !== null,
            'steps'     => function () {
                $unit  = fix_first_unit(['plesk-sophos-av.service', 'sav-protect.service']);
                $steps = [['/usr/bin/systemctl', 'enable', '--now', $unit]];
                // El temporizador de firmas es opcional: un antivirus con las
                // definiciones congeladas sirve de poco, pero si la instalacion
                // no lo trae tampoco es motivo para fallar.
                if (fix_unit_exists('plesk-sophos-av-updater.timer')) {
                    $steps[] = ['/usr/bin/systemctl', 'enable', '--now', 'plesk-sophos-av-updater.timer'];
                }
                return $steps;
            },
            'check'   => fn() => ['/usr/bin/systemctl', 'is-active',
                                  (string) fix_first_unit(['plesk-sophos-av.service', 'sav-protect.service'])],
            'expect'  => '/^active$/m',
            'timeout' => 60,
        ],

        // --------------------------------------------------------- Plesk ---
        'plesk.autoupdates' => [
            'applies'   => ['plesk.updater'],
            'label'     => 'Activar las actualizaciones del panel',
            'desc'      => 'Le dice a Plesk que instale solo sus propias actualizaciones. Cambia una '
                         . 'preferencia del panel; no actualiza nada en este momento ni reinicia servicios.',
            'available' => fn() => plesk_bin() !== null,
            'steps'     => fn() => [[(string) plesk_bin(), 'bin', 'server_pref', '--update', '-autoupdates', 'true']],
            // Relectura directa de lo que se acaba de escribir. La prueba de
            // verdad la da la recomprobacion posterior, que vuelve a mirar
            // 'disable_updater' en la base de datos del panel, que es de donde
            // sale el hallazgo.
            'check'     => fn() => [(string) plesk_bin(), 'bin', 'server_pref', '--show'],
            'expect'    => '/^autoupdates:\s*true/mi',
            'timeout'   => 60,
        ],
    ];
}

/**
 * Definicion de una correccion, o null si la clave no esta en el catalogo.
 *
 * Esta es la unica puerta de entrada valida: el ejecutor resuelve aqui lo que
 * le llega desde la cola, y si devuelve null no ejecuta nada.
 */
function fix_get(string $key): ?array
{
    $cat = fix_catalog();
    return $cat[$key] ?? null;
}

/**
 * Metadatos publicos de la correccion que resuelve un hallazgo, si la hay.
 *
 * Devuelve solo clave, etiqueta y descripcion: el estado se sirve entero al
 * navegador, asi que los comandos no salen de aqui.
 */
function fix_for_finding(string $findingId): ?array
{
    foreach (fix_catalog() as $key => $fix) {
        if (!in_array($findingId, (array) $fix['applies'], true)) {
            continue;
        }
        // Una correccion que no se puede aplicar en esta maquina es peor que
        // ninguna: el boton prometeria algo que solo puede acabar en error.
        if (isset($fix['available']) && !($fix['available'])()) {
            return null;
        }
        return ['key' => $key, 'label' => $fix['label'], 'desc' => $fix['desc']];
    }
    return null;
}

/**
 * Anota los hallazgos con la correccion que les corresponde.
 *
 * Se llama una sola vez en la recogida, con todos los hallazgos ya reunidos.
 * La clave es 'autofix' y no 'fix' porque ese nombre ya lo ocupa el consejo en
 * texto que lleva cada hallazgo desde siempre.
 */
function fixes_annotate(array $findings): array
{
    foreach ($findings as &$f) {
        $fix = fix_for_finding((string) ($f['id'] ?? ''));
        if ($fix !== null) {
            $f['autofix'] = $fix;
        }
    }
    unset($f);
    return $findings;
}

/**
 * Valida el comando que ha construido una entrada del catalogo.
 *
 * El catalogo es cerrado, pero algunos pasos se arman en tiempo de ejecucion
 * (el nombre de la unidad de systemd, la ruta del binario de Plesk). Si algo de
 * eso sale vacio o nulo, lo que llegaria a proc_open seria basura. Es mas
 * barato comprobarlo aqui que descubrirlo con un error raro a medio aplicar.
 */
function fix_argv_ok(array $cmd): bool
{
    if ($cmd === []) {
        return false;
    }
    foreach ($cmd as $arg) {
        if (!is_string($arg) || $arg === '') {
            return false;
        }
    }
    // Ruta absoluta y ejecutable: nada de confiar en el PATH del servicio.
    return str_starts_with($cmd[0], '/') && is_executable($cmd[0]);
}
