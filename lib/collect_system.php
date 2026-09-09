<?php
/**
 * Centinela - recoleccion de estado del sistema base.
 * Soporta familia Debian (apt) y familia RHEL (dnf/yum), que son las dos
 * sobre las que Plesk puede estar instalado.
 */

declare(strict_types=1);

/** Detecta la familia de la distribucion: 'debian' | 'rhel' | 'unknown'. */
function os_family(): string
{
    static $fam = null;
    if ($fam !== null) {
        return $fam;
    }
    if (have('apt-get') && is_file('/etc/debian_version')) {
        return $fam = 'debian';
    }
    if (have('dnf') || have('yum')) {
        return $fam = 'rhel';
    }
    return $fam = 'unknown';
}

/** Informacion general de la maquina. */
function collect_system(): array
{
    $osr = [];
    foreach (explode("\n", (string) slurp('/etc/os-release')) as $line) {
        if (str_contains($line, '=')) {
            [$k, $v] = explode('=', $line, 2);
            $osr[$k] = trim($v, "\" \t");
        }
    }

    $running   = trim((string) run_out(['/usr/bin/uname', '-r'], 5));
    $installed = newest_installed_kernel();

    // Carga y memoria
    $load    = sys_getloadavg() ?: [0, 0, 0];
    $cores   = (int) run_out(['/usr/bin/nproc'], 5) ?: 1;
    $meminfo = [];
    foreach (explode("\n", (string) slurp('/proc/meminfo')) as $line) {
        if (preg_match('/^(\w+):\s+(\d+) kB/', $line, $m)) {
            $meminfo[$m[1]] = (int) $m[2] * 1024;
        }
    }
    $memTotal = $meminfo['MemTotal'] ?? 0;
    $memAvail = $meminfo['MemAvailable'] ?? 0;

    // Discos: solo sistemas de ficheros reales
    $disks = [];
    foreach (explode("\n", sh("df -PB1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2")) as $line) {
        $f = preg_split('/\s+/', trim($line));
        if (count($f) >= 6 && is_numeric($f[1])) {
            $disks[$f[5]] = [
                'mount'   => $f[5],
                'device'  => $f[0],
                'total'   => (int) $f[1],
                'used'    => (int) $f[2],
                'free'    => (int) $f[3],
                'percent' => (int) rtrim($f[4], '%'),
            ];
        }
    }

    $uptime  = (float) explode(' ', (string) slurp('/proc/uptime'))[0];
    $rebootF = '/var/run/reboot-required';
    $needsReboot = is_file($rebootF);
    $rebootPkgs  = [];
    if (is_file($rebootF . '.pkgs')) {
        $rebootPkgs = array_values(array_filter(explode("\n", trim((string) slurp($rebootF . '.pkgs')))));
    }
    // En RHEL el equivalente es needs-restarting -r
    if (!$needsReboot && os_family() === 'rhel' && have('needs-restarting')) {
        $needsReboot = !run(['/usr/bin/needs-restarting', '-r'], 20)['ok'];
    }
    // Un kernel instalado mas nuevo que el que corre implica reinicio pendiente
    if (!$needsReboot && $installed && vnum($installed) > vnum($running)) {
        $needsReboot = true;
    }

    $findings = [];
    if ($needsReboot) {
        $extra = $installed && vnum($installed) > vnum($running)
            ? "En ejecucion {$running}, instalado {$installed}."
            : '';
        $findings[] = finding(
            'sys.reboot',
            SEV_CRIT,
            'Reinicio pendiente',
            trim($extra . ' ' . ($rebootPkgs ? 'Paquetes: ' . implode(', ', $rebootPkgs) : '')),
            'Programar reinicio en ventana de mantenimiento',
            guide(
                'El parche ya esta en disco pero el sistema sigue ejecutando la version anterior en '
                . 'memoria. Hasta que no se reinicie, la vulnerabilidad corregida sigue explotable.',
                [
                    ['do' => 'Mira que paquetes piden el reinicio y desde cuando',
                     'cmd' => 'cat /var/run/reboot-required.pkgs 2>/dev/null; ls -l --time-style=long-iso /var/run/reboot-required 2>/dev/null'],
                    ['do' => 'Comprueba que no hay copias de seguridad ni tareas largas en marcha',
                     'cmd' => 'systemctl list-jobs; who'],
                    ['do' => 'Elige una franja de baja actividad y reinicia',
                     'cmd' => 'systemctl reboot'],
                    ['do' => 'Al volver, confirma que no ha quedado ningun servicio caido',
                     'cmd' => 'systemctl --failed'],
                ],
                'test -e /var/run/reboot-required && echo "sigue pendiente" || echo "ya no hace falta reiniciar"',
                'El reinicio corta todo lo que sirve la maquina durante uno o dos minutos: webs, correo y '
                . 'bases de datos. Si administras por SSH, ten a mano el acceso por consola del proveedor.'
            )
        );
    }

    foreach ($disks as $d) {
        if ($d['percent'] >= 90) {
            $findings[] = finding('sys.disk.' . $d['mount'], SEV_CRIT,
                "Disco {$d['mount']} al {$d['percent']}%",
                human_bytes((float) $d['free']) . ' libres',
                'Liberar espacio: logs, backups, copias de seguridad antiguas',
                guide(
                    'Un disco lleno no degrada el servicio: lo para. MySQL deja de aceptar escrituras, el '
                    . 'correo rebota y Plesk no puede ni registrar lo que ocurre.',
                    [
                        ['do' => 'Localiza los directorios que mas ocupan',
                         'cmd' => 'du -x -h -d 2 ' . escapeshellarg($d['mount']) . ' 2>/dev/null | sort -rh | head -25'],
                        ['do' => 'Revisa el gasto de los sospechosos habituales: registros, copias y correo en cola',
                         'cmd' => 'du -sh /var/log /var/lib/psa/dumps /var/www/vhosts/*/logs /var/spool 2>/dev/null | sort -rh'],
                        ['do' => 'Recorta los registros antiguos del journal a lo ultimo util',
                         'cmd' => 'journalctl --vacuum-time=7d'],
                        ['do' => 'Quita paquetes y cache de apt que ya no hacen falta',
                         'cmd' => 'apt-get clean && apt-get autoremove --purge'],
                        ['do' => 'Si el espacio se lo comen las copias de Plesk, baja la retencion en '
                               . 'Herramientas y configuracion > Gestor de copias de seguridad, y borra las antiguas.'],
                        ['do' => 'Busca ficheros grandes ya borrados que un proceso sigue manteniendo abiertos',
                         'cmd' => 'lsof -nP +L1 2>/dev/null | head -20'],
                    ],
                    'df -h ' . escapeshellarg($d['mount']),
                    'No borres nada bajo /var/www/vhosts sin saber de quien es: ahi viven los datos de los clientes.'
                ));
        } elseif ($d['percent'] >= 80) {
            $findings[] = finding('sys.disk.' . $d['mount'], SEV_WARN,
                "Disco {$d['mount']} al {$d['percent']}%",
                human_bytes((float) $d['free']) . ' libres',
                'Revisar que esta creciendo antes de llegar al 90%',
                guide(
                    'Todavia hay margen, pero conviene saber que esta creciendo: casi siempre son registros, '
                    . 'copias de seguridad o volcados de base de datos que nadie rota.',
                    [
                        ['do' => 'Mira donde se va el espacio',
                         'cmd' => 'du -x -h -d 2 ' . escapeshellarg($d['mount']) . ' 2>/dev/null | sort -rh | head -20'],
                        ['do' => 'Comprueba que la rotacion de registros esta haciendo su trabajo',
                         'cmd' => 'logrotate -d /etc/logrotate.conf 2>&1 | tail -30'],
                        ['do' => 'Limita el tamano del journal de forma permanente si es el que crece',
                         'cmd' => 'journalctl --disk-usage'],
                    ],
                    'df -h ' . escapeshellarg($d['mount'])
                ));
        }
    }

    if ($memTotal > 0 && $memAvail / $memTotal < 0.10) {
        $findings[] = finding('sys.mem', SEV_WARN, 'Memoria disponible por debajo del 10%',
            human_bytes((float) $memAvail) . ' de ' . human_bytes((float) $memTotal),
            'Identificar que proceso la consume antes de que actue el matador por falta de memoria',
            guide(
                'Con la memoria al limite el nucleo empieza a matar procesos por su cuenta, y suele elegir '
                . 'justo el que mas memoria usa: la base de datos.',
                [
                    ['do' => 'Ordena los procesos por memoria residente',
                     'cmd' => 'ps -eo pid,comm,rss,pcpu --sort=-rss | head -15'],
                    ['do' => 'Comprueba si el nucleo ya ha matado algo por falta de memoria',
                     'cmd' => 'journalctl -k --since "24 hours ago" | grep -i "out of memory" | tail -20'],
                    ['do' => 'Revisa los limites de los procesos PHP-FPM, que es lo que mas suele crecer en Plesk',
                     'cmd' => 'grep -rE "^(pm|pm\\.max_children|memory_limit)" /opt/plesk/php/*/etc/php-fpm.d/*.conf 2>/dev/null | head'],
                    ['do' => 'Si el pico es puntual, revisa que haya espacio de intercambio como colchon',
                     'cmd' => 'free -h; swapon --show'],
                ],
                'free -h'
            ));
    }

    if ($cores > 0 && $load[0] / $cores > 4) {
        $findings[] = finding('sys.load', SEV_WARN, 'Carga del sistema muy alta',
            sprintf('load %.2f con %d nucleos', $load[0], $cores),
            'Ver que proceso la genera; si no es trabajo legitimo, puede ser un ataque o un minero',
            guide(
                'Una carga sostenida por encima de cuatro veces el numero de nucleos deja el servidor sin '
                . 'capacidad de respuesta. En un servidor comprometido suele ser mineria o un envio masivo de correo.',
                [
                    ['do' => 'Mira quien consume CPU ahora mismo',
                     'cmd' => 'top -b -n 1 -o %CPU | head -20'],
                    ['do' => 'Distingue si la carga es de CPU o de espera de disco',
                     'cmd' => 'vmstat 1 5'],
                    ['do' => 'Comprueba si viene de la cola de correo, causa muy habitual',
                     'cmd' => 'mailq | tail -1'],
                    ['do' => 'Descarta un pico de peticiones web contra un dominio concreto',
                     'cmd' => 'tail -q -n 5000 ' . platform_weblog_glob() . ' 2>/dev/null | awk \'{print $1}\' | sort | uniq -c | sort -rn | head'],
                ],
                'uptime'
            ));
    }

    return [
        'hostname'     => php_uname('n'),
        'os'           => $osr['PRETTY_NAME'] ?? php_uname('s'),
        'os_family'    => os_family(),
        'arch'         => php_uname('m'),
        'kernel'       => ['running' => $running, 'installed' => $installed],
        'needs_reboot' => $needsReboot,
        'reboot_pkgs'  => $rebootPkgs,
        'uptime_sec'   => (int) $uptime,
        'boot_time'    => time() - (int) $uptime,
        'cpu_cores'    => $cores,
        'load'         => ['1' => round($load[0], 2), '5' => round($load[1], 2), '15' => round($load[2], 2)],
        'memory'       => ['total' => $memTotal, 'available' => $memAvail, 'used' => $memTotal - $memAvail],
        'swap'         => ['total' => $meminfo['SwapTotal'] ?? 0, 'free' => $meminfo['SwapFree'] ?? 0],
        'disks'        => array_values($disks),
        'findings'     => $findings,
    ];
}

/** Kernel mas nuevo instalado en disco (no necesariamente el que corre). */
function newest_installed_kernel(): ?string
{
    $versions = [];
    foreach (glob('/boot/vmlinuz-*') ?: [] as $f) {
        $v = substr(basename($f), strlen('vmlinuz-'));
        if ($v !== '') {
            $versions[] = $v;
        }
    }
    if (!$versions) {
        return null;
    }
    usort($versions, fn($a, $b) => vnum($a) <=> vnum($b));
    return end($versions);
}

/** Actualizaciones de paquetes pendientes, separando las de seguridad. */
function collect_updates(): array
{
    $fam      = os_family();
    $pending  = [];
    $security = 0;

    if ($fam === 'debian') {
        // -o para no ensuciar la salida con avisos interactivos
        $raw = sh("LC_ALL=C apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep -E '^Inst '");
        foreach (explode("\n", $raw) as $line) {
            if (!preg_match('/^Inst\s+(\S+)\s+(?:\[(\S+)\]\s+)?\((\S+)\s+(.*?)\)/', $line, $m)) {
                continue;
            }
            $isSec = stripos($m[4], 'security') !== false;
            $pending[] = [
                'name'    => $m[1],
                'from'    => $m[2] ?? '',
                'to'      => $m[3],
                'origin'  => trim(explode(',', $m[4])[0]),
                'security' => $isSec,
            ];
            if ($isSec) {
                $security++;
            }
        }
    } elseif ($fam === 'rhel') {
        $bin = have('dnf') ? 'dnf' : 'yum';
        $raw = sh("LC_ALL=C {$bin} -q check-update 2>/dev/null | grep -E '^[a-zA-Z0-9]' || true", 60);
        foreach (explode("\n", $raw) as $line) {
            $f = preg_split('/\s+/', trim($line));
            if (count($f) >= 3 && str_contains($f[0], '.')) {
                $pending[] = ['name' => $f[0], 'from' => '', 'to' => $f[1], 'origin' => $f[2], 'security' => false];
            }
        }
        $secRaw = sh("LC_ALL=C {$bin} -q updateinfo list security 2>/dev/null | wc -l", 60);
        $security = (int) $secRaw;
    }

    // Actualizaciones automaticas configuradas
    $autoOn = false;
    $autoDetail = 'no configurado';
    if ($fam === 'debian') {
        $conf = (string) sh("cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null");
        $autoOn = (bool) preg_match('/Unattended-Upgrade"?\s+"1"/', $conf);
        $svc = run(['/usr/bin/systemctl', 'is-enabled', 'unattended-upgrades'], 5)['out'];
        $autoDetail = $autoOn ? "unattended-upgrades ({$svc})" : 'unattended-upgrades desactivado';
    } elseif ($fam === 'rhel') {
        $svc = run(['/usr/bin/systemctl', 'is-enabled', 'dnf-automatic.timer'], 5);
        $autoOn = $svc['ok'];
        $autoDetail = $autoOn ? 'dnf-automatic.timer activo' : 'dnf-automatic no activo';
    }

    $findings = [];
    if ($security > 0) {
        $findings[] = finding('upd.security', SEV_CRIT,
            "{$security} actualizacion(es) de seguridad pendientes",
            'Paquetes con parches publicados sin aplicar',
            $fam === 'debian' ? 'apt-get update && apt-get upgrade' : 'dnf update --security',
            $fam === 'debian'
                ? guide(
                    'Son fallos ya publicos y con parche disponible: cualquiera puede consultar de que se '
                    . 'trata y buscar servidores sin actualizar. Es la via de entrada mas barata que existe.',
                    [
                        ['do' => 'Refresca la lista de paquetes y mira exactamente que se va a tocar',
                         'cmd' => 'apt-get update && apt-get -s upgrade | grep ^Inst'],
                        ['do' => 'Aplica primero solo lo de seguridad si prefieres ir por partes',
                         'cmd' => 'unattended-upgrade --dry-run -d'],
                        ['do' => 'Aplica las actualizaciones',
                         'cmd' => 'apt-get update && apt-get upgrade'],
                        ['do' => 'Comprueba si alguna requiere reiniciar servicios o la maquina',
                         'cmd' => 'test -e /var/run/reboot-required && cat /var/run/reboot-required.pkgs'],
                    ],
                    'apt-get -s upgrade | grep -c ^Inst',
                    'Si actualiza openssl, mysql o php conviene reiniciar despues los servicios afectados; '
                    . 'hazlo en una franja de baja actividad.'
                  )
                : guide(
                    'Son fallos ya publicos y con parche disponible: cualquiera puede consultar de que se '
                    . 'trata y buscar servidores sin actualizar.',
                    [
                        ['do' => 'Consulta el detalle de los avisos pendientes',
                         'cmd' => 'dnf updateinfo list security'],
                        ['do' => 'Aplica solo los parches de seguridad',
                         'cmd' => 'dnf update --security'],
                        ['do' => 'Comprueba si hace falta reiniciar',
                         'cmd' => 'needs-restarting -r'],
                    ],
                    'dnf updateinfo list security | wc -l'
                  ));
    }
    if (count($pending) > 30) {
        $findings[] = finding('upd.backlog', SEV_WARN,
            count($pending) . ' paquetes sin actualizar',
            'Acumulacion grande de paquetes desactualizados',
            'Ponerse al dia por tandas, empezando por lo que no arrastra dependencias',
            guide(
                'Cuanto mas se acumula, mas grande y arriesgada es la actualizacion que toca hacer algun dia, '
                . 'y mas probable que una de esas versiones tenga un fallo conocido.',
                [
                    ['do' => 'Revisa la lista completa antes de nada',
                     'cmd' => 'apt-get update && apt list --upgradable'],
                    ['do' => 'Actualiza sin instalar ni quitar paquetes nuevos, que es la operacion mas segura',
                     'cmd' => 'apt-get upgrade'],
                    ['do' => 'Si quedan paquetes retenidos, mira que dependencia los bloquea',
                     'cmd' => 'apt-mark showhold; apt-get -s dist-upgrade | tail -20'],
                    ['do' => 'Comprueba que ningun servicio se ha quedado por el camino',
                     'cmd' => 'systemctl --failed'],
                ],
                'apt list --upgradable 2>/dev/null | wc -l',
                'Haz copia de seguridad de la suscripcion antes de una actualizacion grande, y evita '
                . 'dist-upgrade a ciegas en un servidor con Plesk: puede cambiar versiones de PHP o MySQL.'
            ));
    }
    if (!$autoOn) {
        $findings[] = finding('upd.auto', SEV_WARN, 'Actualizaciones automaticas desactivadas',
            $autoDetail, 'Activar unattended-upgrades o dnf-automatic para parches de seguridad',
            $fam === 'debian'
                ? guide(
                    'Sin esto, entre que se publica un parche y alguien entra a aplicarlo pueden pasar semanas. '
                    . 'Limitado a los repositorios de seguridad, el riesgo de que rompa algo es muy bajo.',
                    [
                        ['do' => 'Instala el paquete si falta',
                         'cmd' => 'apt-get install unattended-upgrades'],
                        ['do' => 'Activa la tarea con el asistente, que escribe 20auto-upgrades por ti',
                         'cmd' => 'dpkg-reconfigure -plow unattended-upgrades'],
                        ['do' => 'Comprueba que solo tiene habilitado el origen de seguridad',
                         'cmd' => 'grep -A6 "Allowed-Origins\|Origins-Pattern" /etc/apt/apt.conf.d/50unattended-upgrades'],
                        ['do' => 'Haz una pasada en seco para ver que aplicaria',
                         'cmd' => 'unattended-upgrade --dry-run -d'],
                    ],
                    'systemctl is-enabled unattended-upgrades; cat /etc/apt/apt.conf.d/20auto-upgrades',
                    'No dejes activado Unattended-Upgrade::Automatic-Reboot en un servidor de produccion sin '
                    . 'haber decidido antes a que hora puede reiniciarse.'
                  )
                : guide(
                    'Sin esto, entre que se publica un parche y alguien entra a aplicarlo pueden pasar semanas.',
                    [
                        ['do' => 'Instala el automatizador', 'cmd' => 'dnf install dnf-automatic'],
                        ['do' => 'Deja upgrade_type = security en la configuracion',
                         'cmd' => 'sed -i "s/^upgrade_type.*/upgrade_type = security/" /etc/dnf/automatic.conf'],
                        ['do' => 'Activa el temporizador', 'cmd' => 'systemctl enable --now dnf-automatic.timer'],
                    ],
                    'systemctl is-enabled dnf-automatic.timer'
                  ));
    }

    return [
        'total'       => count($pending),
        'security'    => $security,
        'packages'    => array_slice($pending, 0, 100),
        'auto_enabled' => $autoOn,
        'auto_detail' => $autoDetail,
        'findings'    => $findings,
    ];
}

/** Estado de los servicios criticos que suele orquestar Plesk. */
function collect_services(): array
{
    $watch = [
        'sshd'       => ['sshd', 'ssh'],
        'web'        => ['nginx', 'apache2', 'httpd'],
        'mail_smtp'  => ['postfix', 'qmail'],
        'mail_imap'  => ['dovecot'],
        'db'         => ['mariadb', 'mysql', 'mysqld'],
        'dns'        => ['named', 'bind9'],
        'fail2ban'   => ['fail2ban'],
        'ftp'        => ['xinetd', 'proftpd', 'vsftpd'],
        'plesk_panel' => ['sw-cp-server'],
        'plesk_task' => ['sw-engine'],
    ];

    $out = [];
    $findings = [];
    foreach ($watch as $role => $units) {
        $found = null;
        foreach ($units as $u) {
            $st = run(['/usr/bin/systemctl', 'show', $u, '--property=ActiveState,SubState,UnitFileState,LoadState'], 5);
            $props = [];
            foreach (explode("\n", $st['out']) as $l) {
                if (str_contains($l, '=')) {
                    [$k, $v] = explode('=', $l, 2);
                    $props[$k] = $v;
                }
            }
            if (($props['LoadState'] ?? 'not-found') === 'not-found') {
                continue;
            }
            $found = [
                'role'    => $role,
                'unit'    => $u,
                'active'  => $props['ActiveState'] ?? 'unknown',
                'sub'     => $props['SubState'] ?? '',
                'enabled' => $props['UnitFileState'] ?? '',
            ];
            if ($found['active'] === 'active') {
                break; // preferimos el que este corriendo
            }
        }
        if ($found === null) {
            continue; // el rol no aplica en este servidor
        }
        $out[] = $found;

        // Solo alertamos de servicios que estan instalados y habilitados pero caidos
        if ($found['active'] !== 'active' && str_starts_with($found['enabled'], 'enabled')) {
            $findings[] = finding('svc.' . $found['unit'], SEV_CRIT,
                "Servicio {$found['unit']} caido",
                "Habilitado en el arranque pero su estado es {$found['active']}",
                "systemctl status {$found['unit']}",
                guide(
                    'Esta configurado para arrancar solo, asi que no esta parado a proposito: o ha fallado al '
                    . 'arrancar o se ha caido despues. Si es fail2ban o el cortafuegos, ademas te has quedado sin defensa.',
                    [
                        ['do' => 'Lee el motivo exacto de la parada',
                         'cmd' => "systemctl status {$found['unit']} --no-pager -l"],
                        ['do' => 'Revisa las ultimas lineas de su registro',
                         'cmd' => "journalctl -u {$found['unit']} -n 80 --no-pager"],
                        ['do' => 'Si el fallo fue por configuracion, corrigela y vuelve a arrancarlo',
                         'cmd' => "systemctl start {$found['unit']}"],
                        ['do' => 'Comprueba que no lo tumba la falta de memoria o de disco',
                         'cmd' => 'free -h; df -h /'],
                    ],
                    "systemctl is-active {$found['unit']}"
                ));
        }
    }

    return ['services' => $out, 'findings' => $findings];
}

/** Puertos en escucha, distinguiendo los expuestos a Internet. */
function collect_ports(): array
{
    $raw = sh("ss -tulnpH 2>/dev/null");
    $ports = [];
    foreach (explode("\n", $raw) as $line) {
        $f = preg_split('/\s+/', trim($line));
        if (count($f) < 5) {
            continue;
        }
        $proto = $f[0];
        $local = $f[4];
        if (!preg_match('/^(.*):(\d+)$/', $local, $m)) {
            continue;
        }
        $addr = trim($m[1], '[]');
        $port = (int) $m[2];
        $procs = [];
        if (preg_match_all('/"([^"]+)"/', $line, $pm)) {
            $procs = array_values(array_unique($pm[1]));
        }
        // Publico = escucha en comodin o en una IP no de loopback
        $isLocal  = $addr === '127.0.0.1' || $addr === '::1' || str_starts_with($addr, '127.');
        $isPublic = !$isLocal;

        $key = $proto . '/' . $port . '/' . $addr;
        $ports[$key] = [
            'proto'   => $proto,
            'port'    => $port,
            'address' => $addr,
            'public'  => $isPublic,
            'process' => $procs[0] ?? '',
        ];
    }
    ksort($ports);
    $ports = array_values($ports);

    // Servicios en claro que conviene revisar si estan expuestos
    $plaintext = [21 => 'FTP', 23 => 'Telnet', 110 => 'POP3', 143 => 'IMAP', 3306 => 'MySQL', 5432 => 'PostgreSQL'];
    $findings  = [];
    $exposedDb = [];
    $exposedPlain = [];
    foreach ($ports as $p) {
        if (!$p['public']) {
            continue;
        }
        if (in_array($p['port'], [3306, 5432, 27017, 6379, 11211, 9200], true)) {
            $exposedDb[] = $p['port'] . '/' . $p['proto'];
        } elseif (isset($plaintext[$p['port']])) {
            $exposedPlain[] = $plaintext[$p['port']];
        }
    }
    if ($exposedDb) {
        $findings[] = finding('port.db', SEV_CRIT, 'Base de datos o cache expuesta a la red',
            'Puertos: ' . implode(', ', array_unique($exposedDb)),
            'Vincular a 127.0.0.1 o bloquear en el firewall',
            guide(
                'Una base de datos alcanzable desde internet recibe intentos de acceso constantes y basta una '
                . 'contrasena floja para perderlo todo. Redis y Memcached son peores: muchas veces ni piden credenciales.',
                [
                    ['do' => 'Confirma en que direccion escucha cada servicio',
                     'cmd' => 'ss -lntp | grep -E ":(3306|5432|6379|11211|27017)\\b"'],
                    ['do' => 'En MariaDB o MySQL, atalo al bucle local',
                     'cmd' => 'echo -e "[mysqld]\\nbind-address = 127.0.0.1" > /etc/mysql/mysql.conf.d/99-bind-local.cnf && systemctl restart mariadb 2>/dev/null || systemctl restart mysql'],
                    ['do' => 'En Redis, lo mismo, y ademas exige contrasena',
                     'cmd' => 'sed -i "s/^bind .*/bind 127.0.0.1 ::1/" /etc/redis/redis.conf && systemctl restart redis-server'],
                    ['do' => 'Si algo remoto tiene que conectarse de verdad, no lo abras al mundo: limita el '
                           . 'acceso a su IP en el cortafuegos de Plesk (Herramientas y configuracion > Cortafuegos).'],
                ],
                'ss -lntp | grep -E ":(3306|5432|6379|11211|27017)\\b" | grep -v "127.0.0.1\\|\\[::1\\]"',
                'Si alguna aplicacion conecta por la IP publica en vez de por localhost, dejara de funcionar al '
                . 'atarlo: revisa antes las cadenas de conexion.'
            ));
    }
    if ($exposedPlain) {
        $findings[] = finding('port.plain', SEV_INFO, 'Servicios sin cifrado accesibles',
            implode(', ', array_unique($exposedPlain)) . '. Normal en un panel de hosting, pero conviene forzar TLS en los clientes.',
            'Obligar a TLS en correo y FTP, o cerrar el puerto si nadie lo usa',
            guide(
                'Estos puertos siguen abiertos por compatibilidad, pero quien los use envia su contrasena en '
                . 'claro. En una red compartida o un wifi publico, esa contrasena es de quien la quiera leer.',
                [
                    ['do' => 'Comprueba si alguien los esta usando de verdad antes de tocarlos',
                     'cmd' => 'grep -h "login\|LOGIN" /var/log/maillog /var/log/mail.log 2>/dev/null | tail -50'],
                    ['do' => 'En Plesk, exige cifrado en correo desde Herramientas y configuracion > Ajustes del '
                           . 'servidor de correo, marcando el uso obligatorio de conexiones seguras.'],
                    ['do' => 'Para FTP, activa Solo FTPS en Herramientas y configuracion > Ajustes generales > '
                           . 'Configuracion de FTP; ProFTPD seguira escuchando pero rechazara el texto plano.'],
                    ['do' => 'Si un puerto no lo usa nadie, cierralo en el cortafuegos en vez de dejarlo escuchando.'],
                ],
                'ss -lntp | grep -E ":(21|110|143|25)\\b"'
            ));
    }

    return ['ports' => $ports, 'findings' => $findings];
}
