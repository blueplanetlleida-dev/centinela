<?php
/**
 * Centinela - postura de seguridad: fail2ban, firewall, SSH y cuentas.
 */

declare(strict_types=1);

/**
 * Mapa completo de IP bloqueada -> jails que la retienen.
 *
 * Una sola llamada y sin el tope por jail de la lista que se muestra, porque
 * de esto depende saber si un atacante esta suelto: una lista recortada daria
 * por libre a quien si esta bloqueado. Vive aparte del modulo completo porque
 * el vigilante de incidentes la necesita sin pagar el resto de la recogida.
 */
function fail2ban_banned_map(): array
{
    if (!have('fail2ban-client')) {
        return [];
    }
    $banned = [];
    $raw = run(['/usr/bin/fail2ban-client', 'banned'], 20)['out'];
    if (preg_match_all("/'([a-zA-Z0-9._-]+)':\\s*\\[([^\\]]*)\\]/", $raw, $mm, PREG_SET_ORDER)) {
        foreach ($mm as $m) {
            if (preg_match_all("/'([^']+)'/", $m[2], $ipm)) {
                foreach ($ipm[1] as $bip) {
                    if (filter_var($bip, FILTER_VALIDATE_IP) && count($banned) < 5000) {
                        $banned[$bip][] = $m[1];
                    }
                }
            }
        }
    }
    return $banned;
}

/** Estado de fail2ban y de cada jail. */
function collect_fail2ban(): array
{
    if (!have('fail2ban-client')) {
        return [
            'installed' => false,
            'jails'     => [],
            'findings'  => [finding('f2b.missing', SEV_CRIT, 'fail2ban no instalado',
                'Sin bloqueo automatico de fuerza bruta',
                'Activar en Plesk: Herramientas y configuracion > Proteccion contra ataques de fuerza bruta',
                guide(
                    'Sin fail2ban, una botnet puede probar contrasenas contra SSH, el correo o el panel '
                    . 'durante dias sin que nada la corte. Es la defensa que convierte miles de intentos en unos pocos.',
                    [
                        ['do' => 'En Plesk se instala como componente: entra en Herramientas y configuracion > '
                               . 'Actualizaciones y anade Fail2Ban, o hazlo desde la linea de comandos',
                         'cmd' => 'plesk installer --select-release-current --install-component fail2ban'],
                        ['do' => 'Activa la proteccion y los jails que te interesen en Herramientas y '
                               . 'configuracion > Proteccion contra ataques de fuerza bruta.'],
                        ['do' => 'Comprueba que ha arrancado y esta filtrando',
                         'cmd' => 'fail2ban-client status'],
                    ],
                    'systemctl is-active fail2ban && fail2ban-client status',
                    'Anade tu propia IP a la lista de confianza antes de activarlo, o un despiste tecleando la '
                    . 'contrasena puede dejarte fuera del servidor.'
                ))],
        ];
    }

    $active = trim(sh("systemctl is-active fail2ban 2>/dev/null")) === 'active';
    if (!$active) {
        return [
            'installed' => true,
            'active'    => false,
            'jails'     => [],
            'findings'  => [finding('f2b.down', SEV_CRIT, 'fail2ban instalado pero parado',
                'Los jails no estan filtrando', 'systemctl start fail2ban',
                guide(
                    'Esta instalado pero no corre: las reglas de bloqueo no existen ahora mismo, asi que los '
                    . 'intentos de fuerza bruta llegan sin freno. Suele quedarse parado tras un error de configuracion.',
                    [
                        ['do' => 'Mira por que esta parado',
                         'cmd' => 'systemctl status fail2ban --no-pager -l; journalctl -u fail2ban -n 50 --no-pager'],
                        ['do' => 'Valida la configuracion antes de insistir, que casi siempre el fallo esta ahi',
                         'cmd' => 'fail2ban-client -t'],
                        ['do' => 'Arrancalo y dejalo habilitado en el arranque',
                         'cmd' => 'systemctl enable --now fail2ban'],
                        ['do' => 'Comprueba que los jails vuelven a estar activos',
                         'cmd' => 'fail2ban-client status'],
                    ],
                    'systemctl is-active fail2ban'
                ))],
        ];
    }

    $status = run(['/usr/bin/fail2ban-client', 'status'], 20)['out'];
    $names  = [];
    if (preg_match('/Jail list:\s*(.*)$/m', $status, $m)) {
        $names = array_values(array_filter(array_map('trim', explode(',', $m[1]))));
    }

    $jails = [];
    $totalBanned = $totalCurrent = 0;
    foreach ($names as $name) {
        if (!preg_match('/^[a-zA-Z0-9._-]+$/', $name)) {
            continue;
        }
        $out = run(['/usr/bin/fail2ban-client', 'status', $name], 15)['out'];
        $cur = (int) (match1('/Currently banned:\s+(\d+)/', $out) ?? 0);
        $tot = (int) (match1('/Total banned:\s+(\d+)/', $out) ?? 0);
        $fail = (int) (match1('/Currently failed:\s+(\d+)/', $out) ?? 0);
        $ips = [];
        if (preg_match('/Banned IP list:\s*(.*)$/m', $out, $mm)) {
            $ips = array_values(array_filter(preg_split('/\s+/', trim($mm[1]))));
        }
        $jails[] = [
            'name'      => $name,
            'currently' => $cur,
            'total'     => $tot,
            'failed'    => $fail,
            'ips'       => array_slice($ips, 0, 200),
        ];
        $totalBanned  += $tot;
        $totalCurrent += $cur;
    }
    usort($jails, fn($a, $b) => $b['currently'] <=> $a['currently']);

    $banned = fail2ban_banned_map();

    $findings = [];
    if (!$names) {
        $findings[] = finding('f2b.nojails', SEV_WARN, 'fail2ban corriendo sin jails activos',
            'El servicio esta vivo pero no vigila ningun registro', 'Revisar la configuracion de jails',
            guide(
                'Un fail2ban sin jails es decorativo: el proceso corre, pero no hay nada que lea los registros '
                . 'ni que bloquee a nadie.',
                [
                    ['do' => 'Confirma que efectivamente no hay ninguno cargado',
                     'cmd' => 'fail2ban-client status'],
                    ['do' => 'En Plesk, activa los jails desde Herramientas y configuracion > Proteccion contra '
                           . 'ataques de fuerza bruta: como minimo ssh, plesk-panel, dovecot y postfix.'],
                    ['do' => 'Si lo llevas a mano, habilita el jail en jail.local y recarga',
                     'cmd' => 'fail2ban-client reload'],
                    ['do' => 'Verifica que uno concreto esta leyendo su registro',
                     'cmd' => 'fail2ban-client status sshd'],
                ],
                'fail2ban-client status | grep "Jail list"'
            ));
    }

    return [
        'installed'      => true,
        'active'         => true,
        'jails'          => $jails,
        'total_banned'   => $totalBanned,
        'currently_banned' => $totalCurrent,
        'banned_map'     => $banned,
        'findings'       => $findings,
    ];
}

/** Estado del cortafuegos de paquetes. */
function collect_firewall(): array
{
    $res = ['backend' => 'ninguno', 'default_input' => '', 'rules' => 0, 'active' => false];
    $findings = [];

    if (have('nft') && trim(sh("nft list ruleset 2>/dev/null | head -1")) !== '') {
        $res['backend'] = 'nftables';
        $ruleset = sh("nft list ruleset 2>/dev/null");
        $res['rules'] = substr_count($ruleset, "\n");
        $res['default_input'] = match1('/hook input.*?policy (\w+)/s', $ruleset) ?? '';
        $res['active'] = true;
    }

    if (have('iptables')) {
        $save = sh("iptables-save 2>/dev/null");
        if ($save !== '') {
            $ipt = ['rules' => substr_count($save, "\n-A "), 'policy' => match1('/:INPUT (\w+)/', $save) ?? ''];
            if ($ipt['rules'] > 0 || $ipt['policy'] === 'DROP') {
                $res['backend'] = $res['backend'] === 'nftables' ? 'nftables+iptables' : 'iptables';
                $res['rules'] = max($res['rules'], $ipt['rules']);
                $res['default_input'] = $res['default_input'] ?: $ipt['policy'];
                $res['active'] = true;
            }
        }
    }

    // firewalld / ufw como capa de gestion
    foreach (['firewalld' => 'firewalld', 'ufw' => 'ufw'] as $svc => $label) {
        if (trim(sh("systemctl is-active {$svc} 2>/dev/null")) === 'active') {
            $res['manager'] = $label;
        }
    }

    $policy = strtoupper($res['default_input']);
    if (!$res['active']) {
        $findings[] = finding('fw.none', SEV_CRIT, 'Sin cortafuegos de paquetes activo',
            'Todos los puertos en escucha quedan alcanzables',
            'Activar la extension Firewall de Plesk',
            guide(
                'Sin cortafuegos, cualquier servicio que arranque queda publicado en internet sin que nadie lo '
                . 'decida: basta un demonio de pruebas o una base de datos mal atada para abrir la puerta.',
                [
                    ['do' => 'Mira que estas exponiendo ahora mismo',
                     'cmd' => 'ss -lntup'],
                    ['do' => 'Instala la extension Firewall de Plesk, que gestiona las reglas sin pelearse con Plesk',
                     'cmd' => 'plesk bin extension --install firewall'],
                    ['do' => 'Configurala en Herramientas y configuracion > Cortafuegos: deja pasar lo necesario '
                           . '(22, 80, 443, correo y los puertos del panel) y bloquea el resto por defecto.'],
                    ['do' => 'Aplica las reglas y confirmalas dentro del plazo que da Plesk antes de revertir.'],
                ],
                'nft list ruleset | head -20; iptables -S | head -20',
                'Aplicar reglas nuevas puede cortarte la sesion SSH. Plesk revierte solo si no confirmas: usa esa '
                . 'red de seguridad y no confirmes hasta comprobar que sigues dentro.'
            ));
    } elseif ($policy === 'ACCEPT') {
        $findings[] = finding('fw.policy', SEV_WARN, 'Politica por defecto de INPUT en ACCEPT',
            'El cortafuegos filtra por reglas, no por denegacion por defecto',
            'Cambiar la politica por defecto a DROP y permitir solo lo necesario',
            guide(
                'Con la politica en ACCEPT, todo lo que no este expresamente bloqueado entra. El criterio sano '
                . 'es el contrario: se bloquea todo y se abre solo lo que hace falta, de modo que un servicio '
                . 'nuevo no quede expuesto por olvido.',
                [
                    ['do' => 'Anota que puertos estas usando de verdad, para no dejarte ninguno fuera',
                     'cmd' => 'ss -lntu | awk "NR>1 {print \$5}" | sort -u'],
                    ['do' => 'Revisa las reglas actuales',
                     'cmd' => 'iptables -S INPUT | head -40'],
                    ['do' => 'Cambia el modo en Herramientas y configuracion > Cortafuegos de Plesk: la extension '
                           . 'genera la politica restrictiva y mantiene abiertos los puertos que Plesk necesita.'],
                    ['do' => 'Confirma las reglas solo despues de abrir una segunda sesion SSH y comprobar que entra.'],
                ],
                'iptables -S INPUT | head -3',
                'Cambiar la politica a DROP sin permitir antes el puerto de SSH corta tu propia sesion al instante.'
            ));
    }

    return array_merge($res, ['findings' => $findings]);
}

/** Configuracion efectiva de SSH. */
function collect_ssh(): array
{
    $out = sh("sshd -T 2>/dev/null");
    if (trim($out) === '') {
        return ['available' => false, 'findings' => []];
    }

    $cfg = [];
    foreach (explode("\n", $out) as $line) {
        $p = explode(' ', trim($line), 2);
        if (count($p) === 2) {
            $cfg[strtolower($p[0])][] = $p[1];
        }
    }
    $get = fn(string $k, string $d = '') => isset($cfg[$k]) ? $cfg[$k][0] : $d;

    $res = [
        'available'          => true,
        'ports'              => $cfg['port'] ?? ['22'],
        'permit_root_login'  => $get('permitrootlogin'),
        'password_auth'      => $get('passwordauthentication') === 'yes',
        'pubkey_auth'        => $get('pubkeyauthentication') === 'yes',
        'permit_empty_pw'    => $get('permitemptypasswords') === 'yes',
        'max_auth_tries'     => (int) $get('maxauthtries', '6'),
        'x11_forwarding'     => $get('x11forwarding') === 'yes',
        'allow_users'        => $cfg['allowusers'] ?? [],
        'allow_groups'       => $cfg['allowgroups'] ?? [],
    ];

    $findings = [];
    if ($res['permit_empty_pw']) {
        $findings[] = finding('ssh.emptypw', SEV_CRIT, 'SSH permite contrasenas vacias',
            'PermitEmptyPasswords yes', 'Ponerlo en no de inmediato',
            guide(
                'Cualquier cuenta que se quede sin contrasena, aunque sea un instante durante un alta, es una '
                . 'puerta abierta sin nada detras. No hay ningun uso legitimo de esta opcion en un servidor.',
                [
                    ['do' => 'Corrige la directiva',
                     'cmd' => 'sed -i "s/^#\\?PermitEmptyPasswords.*/PermitEmptyPasswords no/" /etc/ssh/sshd_config'],
                    ['do' => 'Valida la sintaxis antes de recargar',
                     'cmd' => 'sshd -t'],
                    ['do' => 'Recarga el servicio; recargar no corta las sesiones abiertas',
                     'cmd' => 'systemctl reload sshd'],
                    ['do' => 'Aprovecha para comprobar que ninguna cuenta esta sin contrasena',
                     'cmd' => 'awk -F: "\$2 == \"\" {print \$1}" /etc/shadow'],
                ],
                'sshd -T | grep -i permitemptypasswords'
            ));
    }
    if ($res['permit_root_login'] === 'yes') {
        $findings[] = finding('ssh.root', SEV_CRIT, 'Login de root por SSH con contrasena permitido',
            'PermitRootLogin yes', 'Cambiar a prohibit-password o no',
            guide(
                'root es el unico usuario cuyo nombre conoce todo el mundo, asi que las botnets solo tienen que '
                . 'acertar la contrasena. Con prohibit-password sigues entrando como root, pero solo con clave.',
                [
                    ['do' => 'Asegurate primero de que tu clave publica funciona: abre otra sesion sin cerrar esta',
                     'cmd' => 'ssh -o PreferredAuthentications=publickey root@' . php_uname('n')],
                    ['do' => 'Cambia la directiva',
                     'cmd' => 'sed -i "s/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/" /etc/ssh/sshd_config'],
                    ['do' => 'Valida y recarga',
                     'cmd' => 'sshd -t && systemctl reload sshd'],
                ],
                'sshd -T | grep -i permitrootlogin',
                'No cierres la sesion actual hasta comprobar en otra ventana que puedes entrar con clave: si la '
                . 'clave no estaba bien instalada, te quedas fuera.'
            ));
    }
    if ($res['password_auth']) {
        $findings[] = finding('ssh.passwd', SEV_WARN, 'Autenticacion por contrasena habilitada en SSH',
            'Expone el servidor a fuerza bruta continua desde botnets',
            'PasswordAuthentication no, tras verificar que las claves publicas funcionan',
            guide(
                'Mientras SSH acepte contrasenas, el servidor recibe intentos automatizados todo el dia y la '
                . 'seguridad depende de que ninguna cuenta tenga una contrasena adivinable. Con claves, ese '
                . 'problema desaparece de raiz.',
                [
                    ['do' => 'Instala tu clave publica si aun no la tienes en el servidor',
                     'cmd' => 'ssh-copy-id -i ~/.ssh/id_ed25519.pub root@' . php_uname('n')],
                    ['do' => 'Comprueba desde tu equipo que entras solo con la clave, sin que te pida contrasena',
                     'cmd' => 'ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no root@' . php_uname('n') . ' true && echo OK'],
                    ['do' => 'Desactiva la autenticacion por contrasena',
                     'cmd' => 'sed -i "s/^#\\?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config'],
                    ['do' => 'Revisa que ningun fichero de /etc/ssh/sshd_config.d la vuelva a activar',
                     'cmd' => 'grep -rn "PasswordAuthentication" /etc/ssh/sshd_config.d/ 2>/dev/null'],
                    ['do' => 'Valida y recarga',
                     'cmd' => 'sshd -t && systemctl reload sshd'],
                ],
                'sshd -T | grep -i "^passwordauthentication"',
                'Hazlo con una segunda sesion abierta. Si tu unica forma de entrar es la contrasena y la '
                . 'desactivas, pierdes el acceso al servidor.'
            ));
    }
    if ($res['max_auth_tries'] > 6) {
        $findings[] = finding('ssh.tries', SEV_INFO, 'MaxAuthTries alto',
            'Valor actual: ' . $res['max_auth_tries'], 'Reducir a 3-4',
            guide(
                'Cada conexion permite tantos intentos como diga este valor, asi que un atacante multiplica sus '
                . 'oportunidades por conexion. Bajarlo encarece la fuerza bruta y hace que fail2ban salte antes.',
                [
                    ['do' => 'Fija un valor razonable',
                     'cmd' => 'sed -i "s/^#\\?MaxAuthTries.*/MaxAuthTries 3/" /etc/ssh/sshd_config'],
                    ['do' => 'Valida y recarga',
                     'cmd' => 'sshd -t && systemctl reload sshd'],
                ],
                'sshd -T | grep -i maxauthtries',
                'Si usas un agente con varias claves cargadas, cada clave cuenta como un intento: con 3 puedes '
                . 'quedarte corto. Indica la clave concreta con IdentityFile en tu ~/.ssh/config.'
            ));
    }

    return array_merge($res, ['findings' => $findings]);
}

/** Auditoria basica de cuentas del sistema. */
function collect_accounts(): array
{
    $shadow = slurp('/etc/shadow');
    $emptyPw = [];
    $noExpire = [];
    if ($shadow !== null) {
        foreach (explode("\n", $shadow) as $line) {
            $f = explode(':', $line);
            if (count($f) < 3) {
                continue;
            }
            if ($f[1] === '') {
                $emptyPw[] = $f[0];
            }
        }
    }

    // Cuentas con UID 0 distintas de root
    $uid0 = [];
    foreach (explode("\n", (string) slurp('/etc/passwd')) as $line) {
        $f = explode(':', $line);
        if (count($f) >= 7 && (int) $f[2] === 0 && $f[0] !== 'root') {
            $uid0[] = $f[0];
        }
    }

    // Cuentas con shell interactiva
    $interactive = [];
    foreach (explode("\n", (string) slurp('/etc/passwd')) as $line) {
        $f = explode(':', $line);
        if (count($f) >= 7 && !preg_match('#/(nologin|false|sync)$#', $f[6]) && (int) $f[2] >= 1000) {
            $interactive[] = ['user' => $f[0], 'uid' => (int) $f[2], 'shell' => $f[6]];
        }
    }

    $findings = [];
    if ($emptyPw) {
        $findings[] = finding('acct.emptypw', SEV_CRIT, 'Cuentas sin contrasena',
            implode(', ', $emptyPw), 'Asignar contrasena o bloquear con passwd -l',
            guide(
                'Una cuenta con el campo de contrasena vacio puede entrar sin credencial alguna alli donde se '
                . 'acepten contrasenas: consola, SSH si lo permite, su desde otra cuenta.',
                [
                    ['do' => 'Confirma la lista y con que shell cuentan',
                     'cmd' => 'awk -F: "\$2 == \"\" {print \$1}" /etc/shadow | while read u; do getent passwd "$u"; done'],
                    ['do' => 'Si la cuenta es de servicio y no debe iniciar sesion, bloqueala',
                     'cmd' => 'passwd -l NOMBRE && usermod -s /usr/sbin/nologin NOMBRE'],
                    ['do' => 'Si es de una persona, asignale una contrasena y obligala a cambiarla',
                     'cmd' => 'passwd NOMBRE && chage -d 0 NOMBRE'],
                ],
                'awk -F: "\$2 == \"\" {print \$1}" /etc/shadow | wc -l',
                'Bloquear una cuenta que use algun servicio para autenticarse puede dejar ese servicio sin '
                . 'funcionar: comprueba a que pertenece antes.'
            ));
    }
    if ($uid0) {
        $findings[] = finding('acct.uid0', SEV_CRIT, 'Cuentas adicionales con UID 0',
            implode(', ', $uid0), 'Revisar: una cuenta UID 0 equivale a root',
            guide(
                'Con UID 0 el nombre da igual: el sistema la trata como root. Es la forma clasica de dejar una '
                . 'puerta trasera que pasa desapercibida en un listado de usuarios.',
                [
                    ['do' => 'Mira quien es y cuando se creo',
                     'cmd' => 'awk -F: "\$3 == 0 {print}" /etc/passwd; ls -l --time-style=long-iso /etc/passwd /etc/shadow'],
                    ['do' => 'Busca en el historial de accesos si esa cuenta ha entrado',
                     'cmd' => 'last -F | head -30; lastlog | awk "NR==1 || !/Never/"'],
                    ['do' => 'Si no la has creado tu, tratalo como una intrusion: no te limites a borrarla, '
                           . 'revisa tareas programadas, claves autorizadas y procesos antes de decidir.',
                     'cmd' => 'crontab -l -u root; ls -l /root/.ssh/authorized_keys; ps -ef --forest | head -40'],
                    ['do' => 'Si era una cuenta administrativa creada a proposito, dale un UID propio y usa sudo',
                     'cmd' => 'usermod -u 1001 NOMBRE && usermod -aG sudo NOMBRE'],
                ],
                'awk -F: "\$3 == 0 {print \$1}" /etc/passwd',
                'Si sospechas de una intrusion, no borres nada todavia: hacerlo destruye las huellas que '
                . 'necesitas para saber por donde entraron.'
            ));
    }

    return [
        'empty_password' => $emptyPw,
        'extra_uid0'     => $uid0,
        'interactive'    => $interactive,
        'findings'       => $findings,
    ];
}
