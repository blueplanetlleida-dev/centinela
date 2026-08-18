<?php
/**
 * Centinela - entregabilidad del correo saliente.
 *
 * La herramienta avisa por correo, asi que un fallo de entrega la deja muda.
 * Este modulo vigila las condiciones que hacen que los grandes proveedores
 * acepten o rechacen el correo del servidor.
 */

declare(strict_types=1);

/** IP publica desde la que sale el correo. */
function primary_public_ip(): ?string
{
    // La IP de la ruta por defecto es la que usara el MTA para salir.
    $out = sh("ip -4 route get 1.1.1.1 2>/dev/null | head -1");
    $ip  = match1('/src\s+([0-9.]+)/', $out);
    if ($ip !== null && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return $ip;
    }
    // Alternativa: la primera IP publica configurada en el sistema
    foreach (explode("\n", sh("ip -4 -o addr show scope global 2>/dev/null")) as $line) {
        $cand = match1('/inet\s+([0-9.]+)/', $line);
        if ($cand !== null && filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $cand;
        }
    }
    return $ip;
}

function collect_mail(): array
{
    $findings = [];
    $res = [
        'ip'          => null,
        'ptr'         => null,
        'fcrdns'      => null,   // ¿el nombre del PTR vuelve a la misma IP?
        'ptr_forward' => null,
        'queue'       => null,
        'bounces_24h' => 0,
        'domains'     => [],
    ];

    $ip = primary_public_ip();
    $res['ip'] = $ip;

    // ¿Esta saliendo el correo de verdad? Un desajuste de DNS es grave si los
    // envios fallan, pero solo un riesgo latente si estan llegando: no tiene
    // sentido marcar en rojo algo que ahora mismo funciona.
    $lastSendFile = state_dir() . '/last_send.json';
    $lastSend = is_readable($lastSendFile) ? json_decode((string) slurp($lastSendFile), true) : null;
    $sendingOk = is_array($lastSend)
        && !empty($lastSend['ok'])
        && (time() - (int) ($lastSend['at'] ?? 0)) < 7 * 86400;

    // ------------------------------------------------ PTR y coincidencia ---
    if ($ip !== null && have('dig')) {
        $ptr = trim(run(['/usr/bin/dig', '+short', '+time=3', '+tries=2', '-x', $ip], 10)['out']);
        $ptr = trim(explode("\n", $ptr)[0]);
        $ptr = rtrim($ptr, '.');
        $res['ptr'] = $ptr !== '' ? $ptr : null;

        if ($res['ptr'] === null) {
            $findings[] = finding('mail.ptr', SEV_CRIT,
                'La IP de salida no tiene DNS inverso',
                "{$ip} sin registro PTR. Gmail y otros proveedores rechazan el correo por politica.",
                'Solicitar al proveedor de la IP que configure el PTR',
                guide(
                    'El PTR es lo primero que mira el servidor que recibe tu correo. Una IP sin nombre inverso se '
                    . 'trata como maquina no identificada, y proveedores como Gmail o Outlook rechazan de entrada.',
                    [
                        ['do' => 'Confirma que no hay PTR publicado',
                         'cmd' => 'dig +short -x ' . escapeshellarg($ip)],
                        ['do' => 'El PTR solo lo puede poner el dueno de la IP: abre un tique a tu proveedor de '
                               . 'hosting pidiendo que apunte ' . $ip . ' al nombre del servidor. En la mayoria de '
                               . 'paneles (Hetzner, OVH, DigitalOcean) se cambia tu mismo en la ficha de la maquina.'],
                        ['do' => 'Asegurate de que ese nombre tiene ademas registro A hacia esta misma IP',
                         'cmd' => 'dig +short A ' . escapeshellarg(php_uname('n'))],
                        ['do' => 'La propagacion del inverso puede tardar unas horas; vuelve a comprobarlo despues.'],
                    ],
                    'dig +short -x ' . escapeshellarg($ip)
                ));
        } else {
            // Comprobacion directa-inversa: el nombre debe resolver a la misma IP
            $fwd = array_filter(array_map('trim', explode("\n",
                run(['/usr/bin/dig', '+short', '+time=3', '+tries=2', $res['ptr'], 'A'], 10)['out'])));
            $fwd = array_values(array_filter($fwd, fn($x) => filter_var($x, FILTER_VALIDATE_IP)));
            $res['ptr_forward'] = $fwd;
            $res['fcrdns'] = in_array($ip, $fwd, true);

            if (!$res['fcrdns']) {
                $detalle = $fwd
                    ? "El PTR apunta a {$res['ptr']}, pero ese nombre resuelve a " . implode(', ', $fwd) . " en vez de a {$ip}."
                    : "El PTR apunta a {$res['ptr']}, pero ese nombre no resuelve a ninguna direccion.";
                $findings[] = finding('mail.fcrdns',
                    $sendingOk ? SEV_WARN : SEV_CRIT,
                    'El DNS directo e inverso no coinciden',
                    $detalle . ($sendingOk
                        ? ' El correo se esta entregando gracias a SPF y DKIM, pero algunos proveedores rechazan por este motivo.'
                        : ' Los grandes proveedores rechazan el correo en esta situacion.'),
                    "Corregir el registro A de {$res['ptr']} para que apunte a {$ip}, sin proxy",
                    guide(
                        'La comprobacion que hace el destinatario es de ida y vuelta: coge la IP, saca su PTR, y '
                        . 'ese nombre tiene que resolver otra vez a la misma IP. Si la cadena se rompe, el correo '
                        . 'entra en la categoria de origen dudoso. La causa mas habitual es que el nombre este '
                        . 'detras de un proxy tipo Cloudflare, que devuelve las IP del proxy en vez de la tuya.',
                        [
                            ['do' => 'Mira los dos lados de la cadena',
                             'cmd' => 'dig +short -x ' . escapeshellarg($ip) . '; dig +short A ' . escapeshellarg($res['ptr'])],
                            ['do' => 'Si el nombre del PTR esta en Cloudflare, ponlo en modo solo DNS (nube gris): '
                                   . 'el nombre del servidor de correo nunca debe ir por el proxy.'],
                            ['do' => 'Si el registro A apunta a otra direccion, corrigelo para que apunte a ' . $ip . '.'],
                            ['do' => 'Si prefieres cambiar el otro extremo, pide al proveedor que el PTR de la IP '
                                   . 'apunte a un nombre que si resuelva aqui.'],
                        ],
                        'test "$(dig +short A ' . escapeshellarg($res['ptr']) . ' | head -1)" = "' . $ip . '" && echo coinciden || echo siguen sin coincidir',
                        '',
                        'https://support.google.com/mail/answer/81126'
                    ));
            }
        }
    }

    // --------------------------------------------------- SPF, DKIM, DMARC ---
    // Revisamos los dominios de correo alojados mas relevantes
    $bin = plesk_bin();
    $domains = [];
    if ($bin !== null) {
        $out = run([$bin, 'db', '-Ne',
            "SELECT d.name FROM domains d JOIN mail m ON m.dom_id = d.id
             WHERE d.parentDomainId = 0 GROUP BY d.name LIMIT 10"], 20)['out'];
        $domains = array_values(array_filter(array_map('trim', explode("\n", $out))));
    }

    $noSpf = $noDmarc = [];
    foreach ($domains as $d) {
        if (!preg_match('/^[a-zA-Z0-9.-]+$/', $d)) {
            continue;
        }
        $txt   = run(['/usr/bin/dig', '+short', '+time=3', $d, 'TXT'], 10)['out'];
        $spf   = (bool) preg_match('/v=spf1/i', $txt);
        $dtxt  = run(['/usr/bin/dig', '+short', '+time=3', '_dmarc.' . $d, 'TXT'], 10)['out'];
        $dmarc = (bool) preg_match('/v=DMARC1/i', $dtxt);
        $ktxt  = run(['/usr/bin/dig', '+short', '+time=3', 'default._domainkey.' . $d, 'TXT'], 10)['out'];
        $dkim  = (bool) preg_match('/v=DKIM1|p=/i', $ktxt);

        $res['domains'][] = ['domain' => $d, 'spf' => $spf, 'dmarc' => $dmarc, 'dkim' => $dkim];
        if (!$spf)   { $noSpf[] = $d; }
        if (!$dmarc) { $noDmarc[] = $d; }
    }

    if ($noSpf) {
        $findings[] = finding('mail.spf', SEV_WARN,
            count($noSpf) . ' dominio(s) de correo sin SPF',
            implode(', ', array_slice($noSpf, 0, 5)),
            'Publicar un registro TXT v=spf1 para autorizar a este servidor',
            guide(
                'SPF es la lista de quien puede enviar correo en nombre del dominio. Sin ella, ni tu correo '
                . 'legitimo tiene con que acreditarse ni nadie impide que un tercero suplante el dominio.',
                [
                    ['do' => 'Comprueba que publica hoy el dominio',
                     'cmd' => 'dig +short TXT DOMINIO | grep -i spf1'],
                    ['do' => 'Publica un TXT en la raiz del dominio autorizando a este servidor. Si el DNS lo lleva '
                           . 'Plesk, con esto basta; si esta en Cloudflare u otro proveedor, hazlo alli',
                     'cmd' => 'plesk bin dns --add DOMINIO -txt "v=spf1 a mx ip4:' . (string) ($res['ip'] ?? '') . ' ~all" -domain DOMINIO'],
                    ['do' => 'Incluye los servicios externos que tambien envien por ti (facturacion, boletines) '
                           . 'con su include, en vez de anadir mas IP sueltas.'],
                    ['do' => 'Espera a que propague y comprueba el resultado',
                     'cmd' => 'dig +short TXT DOMINIO'],
                ],
                'dig +short TXT DOMINIO | grep -i spf1',
                'Un solo registro SPF por dominio: si publicas dos, la comprobacion falla y el resultado es peor '
                . 'que no tener ninguno. Usa ~all mientras verificas, y -all cuando estes seguro.'
            ));
    }
    if ($noDmarc) {
        $findings[] = finding('mail.dmarc', SEV_INFO,
            count($noDmarc) . ' dominio(s) sin politica DMARC',
            implode(', ', array_slice($noDmarc, 0, 5)),
            'Publicar _dmarc con al menos v=DMARC1; p=none',
            guide(
                'DMARC le dice al destinatario que hacer cuando un correo dice venir de tu dominio pero no pasa '
                . 'SPF ni DKIM. Ademas te manda informes de quien lo esta intentando, que es como se detecta una '
                . 'suplantacion antes de que haga dano.',
                [
                    ['do' => 'Asegurate primero de tener SPF y DKIM funcionando: DMARC sin ellos rechaza tu propio correo.'],
                    ['do' => 'Publica la politica en modo observacion, que no bloquea nada',
                     'cmd' => 'plesk bin dns --add DOMINIO -txt "v=DMARC1; p=none; rua=mailto:dmarc@DOMINIO" -domain _dmarc.DOMINIO'],
                    ['do' => 'Revisa durante unas semanas los informes que lleguen a esa direccion.'],
                    ['do' => 'Cuando veas que todo tu correo legitimo pasa, endurece a p=quarantine y luego a p=reject.'],
                ],
                'dig +short TXT _dmarc.DOMINIO',
                'No pases directamente a p=reject: si algun servicio tuyo envia sin estar autorizado, sus correos '
                . 'desapareceran sin aviso.'
            ));
    }

    // ------------------------------------------------------- cola y rebotes -
    if (have('postqueue')) {
        $q = sh("postqueue -p 2>/dev/null | tail -1");
        $res['queue'] = (int) (match1('/(\d+)\s+Request/', $q) ?? 0);
        if ($res['queue'] > 200) {
            $findings[] = finding('mail.queue', SEV_WARN, 'Cola de correo con mucho retraso',
                $res['queue'] . ' mensajes pendientes de entrega',
                'Revisar: postqueue -p',
                guide(
                    'Una cola que crece suele ser una de dos cosas: un destino que te esta rechazando, o una '
                    . 'cuenta comprometida enviando spam desde tu servidor. La segunda acaba en listas negras.',
                    [
                        ['do' => 'Mira que hay en la cola y hacia donde va',
                         'cmd' => 'postqueue -p | tail -40'],
                        ['do' => 'Agrupa por remitente: si casi todo sale de una sola cuenta, esa cuenta esta comprometida',
                         'cmd' => 'postqueue -j 2>/dev/null | head -500 | grep -o \'"sender":"[^"]*"\' | sort | uniq -c | sort -rn | head'],
                        ['do' => 'Lee el motivo del ultimo fallo de un mensaje concreto',
                         'cmd' => 'grep -m5 "status=deferred" /var/log/maillog /var/log/mail.log 2>/dev/null | tail -5'],
                        ['do' => 'Si es spam, cambia la contrasena de la cuenta y borra sus mensajes de la cola',
                         'cmd' => 'plesk bin mail --update CUENTA@DOMINIO -passwd NUEVA; postsuper -d ALL deferred'],
                        ['do' => 'Si es un destino temporalmente caido, reintenta la cola',
                         'cmd' => 'postqueue -f'],
                    ],
                    'postqueue -p | tail -1',
                    'postsuper -d ALL borra correo de forma irreversible. Comprueba antes que lo que hay en la cola '
                    . 'es spam y no correo legitimo atascado.'
                ));
        }
    }

    // Rebotes de las ultimas 24 horas en el log del MTA
    foreach (['/var/log/maillog', '/var/log/mail.log'] as $log) {
        if (!is_readable($log)) {
            continue;
        }
        $since = date('M j', time() - 86400);
        $today = date('M j');
        $n = (int) sh("grep -c 'status=bounced' " . escapeshellarg($log) . " 2>/dev/null || true");
        $res['bounces_24h'] = $n;
        break;
    }

    // Si el propio Centinela no pudo enviar, es lo primero que hay que saber.
    if (is_array($lastSend)) {
        if (!empty($lastSend['error'])) {
            $findings[] = finding('mail.send', SEV_CRIT,
                'Centinela no pudo enviar su ultimo aviso',
                (string) $lastSend['error'],
                'Revisar la configuracion de correo del servidor',
                guide(
                    'Si el panel no puede avisarte, todas las alertas que dependan del correo se pierden en '
                    . 'silencio: te enteraras de la siguiente incidencia solo si entras a mirar.',
                    [
                        ['do' => 'Comprueba que el servidor de correo esta arriba',
                         'cmd' => 'systemctl status postfix --no-pager | head -12'],
                        ['do' => 'Lanza un envio de prueba desde el propio Centinela y mira el error completo',
                         'cmd' => 'centinela-report --test'],
                        ['do' => 'Revisa el registro del MTA justo despues del intento',
                         'cmd' => 'tail -40 /var/log/maillog 2>/dev/null || tail -40 /var/log/mail.log'],
                        ['do' => 'Verifica que el remitente configurado existe y es de un dominio de este servidor',
                         'cmd' => 'grep -A6 "\'mail\'" /etc/centinela/config.php | grep from'],
                    ],
                    'centinela-report --test'
                ));
        }
        $res['last_send'] = $lastSend;
    }

    // Comprobamos que el remitente configurado alinea con el dominio que
    // publica SPF y DKIM: es la causa mas habitual de rechazo silencioso.
    $cfgMail = load_config()['mail'] ?? [];
    $fromDom = strtolower((string) substr(strrchr((string) ($cfgMail['from'] ?? ''), '@') ?: '', 1));
    if ($fromDom !== '' && $res['domains']) {
        $known = array_column($res['domains'], null, 'domain');
        if (isset($known[$fromDom]) && !$known[$fromDom]['spf']) {
            $findings[] = finding('mail.from_align', SEV_WARN,
                'El remitente de los avisos no tiene SPF',
                "Los correos salen como {$cfgMail['from']} y {$fromDom} no publica SPF.",
                'Usar un remitente de un dominio con SPF y DKIM configurados',
                guide(
                    'Los avisos de Centinela salen con un remitente que no puede acreditarse, asi que tienen '
                    . 'muchas papeletas de acabar en la carpeta de correo no deseado justo cuando mas falta hacen.',
                    [
                        ['do' => 'Publica SPF para ' . $fromDom . ' (ver la incidencia de SPF) o elige un remitente '
                               . 'de un dominio que ya lo tenga.'],
                        ['do' => 'Cambia el remitente en la configuracion del panel',
                         'cmd' => 'sed -n "/\'mail\'/,/)/p" /etc/centinela/config.php'],
                        ['do' => 'Comprueba que el nuevo dominio publica SPF y DKIM',
                         'cmd' => 'dig +short TXT ' . escapeshellarg($fromDom) . '; dig +short TXT default._domainkey.' . escapeshellarg($fromDom)],
                        ['do' => 'Envia una prueba y mira donde cae',
                         'cmd' => 'centinela-report --test'],
                    ],
                    'dig +short TXT ' . escapeshellarg($fromDom) . ' | grep -i spf1'
                ));
        }
    }

    return array_merge($res, ['findings' => $findings]);
}
