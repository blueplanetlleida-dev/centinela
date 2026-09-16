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
 * Las correcciones marcadas 'long' no se ejecutan dentro del ejecutor: este
 * abre un trabajo, lo lanza en una unidad transitoria de systemd y responde en
 * el acto. El progreso vive en jobs/<id>.json y el panel lo sondea. Asi apt
 * puede tardar lo que necesite sin chocar con el TimeoutStartSec de la unidad.
 *
 * Que se ha dejado fuera a proposito:
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
 * ¿Es una maquina de la familia Debian?
 *
 * Se comprueba aqui en lugar de tirar de os_family(), que vive en el modulo de
 * recogida del sistema: el ejecutor no carga ese fichero y no merece la pena
 * arrastrarlo entero por una linea.
 */
function fix_is_debian(): bool
{
    return is_file('/etc/debian_version') && is_executable('/usr/bin/apt-get');
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
 *   'long'      si es true, no se ejecuta en linea: se abre un trabajo aparte.
 *               Lo usan las correcciones que pueden tardar minutos.
 *   'env'       variables de entorno extra para los pasos.
 *   'warn'      aviso que el panel destaca antes de confirmar. Reservado para
 *               lo que puede cortar un servicio aunque sea un momento.
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

        // ------------------------------------ actualizaciones (largas) ---
        // Estas dos son el motivo de que exista el modelo de trabajo largo:
        // apt tarda minutos y reinicia servicios por su cuenta.
        'upd.security.apply' => [
            'applies'   => ['upd.security'],
            'label'     => 'Aplicar las de seguridad',
            'desc'      => 'Refresca la lista de paquetes y aplica solo las actualizaciones de los '
                         . 'repositorios de seguridad, con unattended-upgrade, que es quien sabe '
                         . 'cuales son. Puede tardar varios minutos.',
            'warn'      => 'Algunos paquetes reinician su servicio al actualizarse. Si toca el kernel, '
                         . 'despues hara falta reiniciar la maquina: eso no lo hace este boton.',
            'long'      => true,
            'available' => fn() => fix_is_debian() && is_executable('/usr/bin/unattended-upgrade'),
            'steps'     => fn() => [
                ['/usr/bin/apt-get', 'update', '-qq'],
                ['/usr/bin/unattended-upgrade', '-v'],
            ],
            'env'       => ['DEBIAN_FRONTEND' => 'noninteractive', 'NEEDRESTART_MODE' => 'a'],
            'timeout'   => 1800,
        ],

        'upd.backlog.apply' => [
            'applies'   => ['upd.backlog'],
            'label'     => 'Actualizar los paquetes',
            'desc'      => 'Refresca la lista y actualiza los paquetes pendientes conservando los '
                         . 'ficheros de configuracion que ya tengas. No instala ni elimina paquetes '
                         . 'nuevos: lo que necesite dependencias nuevas se queda retenido y hay que '
                         . 'mirarlo a mano.',
            'warn'      => 'Esto reinicia los servicios que se actualicen, incluida la base de datos si '
                         . 'le toca. Mejor fuera de horas de trafico.',
            'long'      => true,
            'available' => fn() => fix_is_debian(),
            'steps'     => fn() => [
                ['/usr/bin/apt-get', 'update', '-qq'],
                // confdef + confold: ante un fichero de configuracion que ha
                // cambiado en el paquete, se queda el que ya hay. Sin esto apt
                // pregunta, y aqui no hay nadie para contestar.
                ['/usr/bin/apt-get', '-y',
                 '-o', 'Dpkg::Options::=--force-confdef',
                 '-o', 'Dpkg::Options::=--force-confold',
                 'upgrade'],
            ],
            'env'       => ['DEBIAN_FRONTEND' => 'noninteractive', 'NEEDRESTART_MODE' => 'a'],
            'timeout'   => 1800,
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
        $meta = ['key' => $key, 'label' => $fix['label'], 'desc' => $fix['desc']];
        // 'long' le dice al panel que espere minutos y sondee el trabajo en vez
        // del resultado inmediato; 'warn' se destaca antes de confirmar.
        if (!empty($fix['long'])) {
            $meta['long'] = true;
        }
        if (!empty($fix['warn'])) {
            $meta['warn'] = $fix['warn'];
        }
        return $meta;
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

// ------------------------------------------------------- trabajos largos ----
//
// Una correccion marcada 'long' no puede ejecutarse dentro del ejecutor: apt
// tarda minutos y la unidad tiene su TimeoutStartSec. En su lugar se abre un
// trabajo, se lanza en una unidad transitoria de systemd y el panel sondea el
// fichero de progreso.
//
// La unidad transitoria se llama siempre igual, 'centinela-job'. No es un
// descuido: es lo que impide que se solapen dos trabajos. systemd se niega a
// arrancar una unidad que ya existe, asi que la exclusion mutua la garantiza el
// propio systemd y no un cerrojo nuestro. Dos apt a la vez acabarian chocando
// por el cerrojo de dpkg de todas formas.

/** Nombre de la unidad transitoria. Uno solo, a proposito. */
const CENT_JOB_UNIT = 'centinela-job';

/** Lineas de salida que se conservan de un trabajo. */
const CENT_JOB_LOG_LINES = 120;

/** Ruta del fichero de progreso de un trabajo. */
function job_path(string $stateDir, string $id): string
{
    return rtrim($stateDir, '/') . '/jobs/' . $id . '.json';
}

/** Lee un trabajo, o null si no existe o esta corrupto. */
function job_read(string $stateDir, string $id): ?array
{
    if (!preg_match('/^[a-f0-9]{8,32}$/', $id)) {
        return null;
    }
    $f = job_path($stateDir, $id);
    if (!is_file($f)) {
        return null;
    }
    $d = json_decode((string) slurp($f), true);
    return is_array($d) ? $d : null;
}

/** Guarda el progreso. Se llama a menudo, asi que el fichero se mantiene corto. */
function job_write(string $stateDir, array $job, ?string $group = null): bool
{
    if (isset($job['log']) && count($job['log']) > CENT_JOB_LOG_LINES) {
        $job['log'] = array_slice($job['log'], -CENT_JOB_LOG_LINES);
    }
    return write_atomic(
        job_path($stateDir, (string) $job['id']),
        json_encode($job, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        0640,
        $group
    );
}

/** Quita los trabajos terminados hace mas de un dia. */
function jobs_prune(string $stateDir): void
{
    foreach (glob(rtrim($stateDir, '/') . '/jobs/*.json') ?: [] as $f) {
        if (time() - (int) @filemtime($f) > 86400) {
            @unlink($f);
        }
    }
}
