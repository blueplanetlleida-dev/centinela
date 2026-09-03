<?php
/**
 * Centinela - analisis de los logs web de los dominios alojados.
 *
 * El log de autenticacion cuenta quien intenta entrar por SSH o por correo.
 * Esto cuenta lo otro: quien busca ficheros que no deberian estar publicados,
 * quien prueba contrasenas contra WordPress y que ha bloqueado ModSecurity.
 * En un servidor de hosting es la via de entrada mas frecuente, y hasta ahora
 * no la miraba nadie.
 *
 * Lectura incremental por fichero (inodo + desplazamiento), igual que el log
 * de autenticacion: cada pasada solo procesa lo nuevo.
 */

declare(strict_types=1);

/** Dias de historico que conservamos del analisis web. */
const CENT_WEB_DAYS = 7;

/** Tope de bytes leidos por fichero y pasada. */
const CENT_WEB_MAX_BYTES = 8388608;

/** Tope de lineas procesadas por pasada, sumando todos los ficheros. */
const CENT_WEB_MAX_LINES = 300000;

/** Peticiones sospechosas en 7 dias para considerar que una IP escanea. */
const CENT_WEB_SCAN_MIN = 60;

/** Peticiones contra el login de WordPress para considerarlo fuerza bruta. */
const CENT_WEB_WP_MIN = 100;

/**
 * Clasifica la ruta pedida. Cadena vacia si no tiene nada de particular.
 *
 * El criterio es «esto no lo pide un visitante»: ficheros de configuracion,
 * copias de seguridad, paneles de administracion ajenos al sitio y rutas de
 * exploits conocidos.
 */
function web_path_category(string $path): string
{
    $p = strtolower($path);

    // Secretos y ficheros que no deberian ser publicos
    foreach (['/.env', '/.git', '/.svn', '/.hg', '/.aws', '/.ssh', 'id_rsa', 'wp-config',
              '/.htpasswd', '/.htaccess', '/credentials', '/config.json', '/configuration.php',
              '/.npmrc', '/.dockercfg', '/docker-compose', '/server-status', '/server-info'] as $x) {
        if (str_contains($p, $x)) {
            return 'secreto';
        }
    }
    // Volcados y copias olvidadas
    foreach (['.sql', '.sql.gz', '.bak', '.old', '.save', '.swp', '.tar.gz', '.zip', '.7z'] as $x) {
        if (str_ends_with($p, $x)) {
            return 'copia';
        }
    }
    // Ejecucion remota y puertas traseras conocidas
    foreach (['/eval-stdin.php', '/vendor/phpunit', 'shell.php', 'cmd.php', '/alfa', '/wso',
              '/c99', '/php-cgi', '/cgi-bin/', '/.axd', 'wp-file-manager', '/uploads/'] as $x) {
        if (str_contains($p, $x)) {
            return 'ejecucion';
        }
    }
    // WordPress
    foreach (['/wp-login.php', '/xmlrpc.php', '/wp-admin', '/wp-json/wp/v2/users'] as $x) {
        if (str_contains($p, $x)) {
            return 'wordpress';
        }
    }
    // Paneles de administracion de terceros
    foreach (['/phpmyadmin', '/pma/', '/adminer', '/administrator', '/manager/html', '/solr/'] as $x) {
        if (str_contains($p, $x)) {
            return 'panel';
        }
    }
    return '';
}

/** Rutas que fallan a todas horas sin que eso signifique nada. */
function web_ruido(string $path): bool
{
    $p = strtolower($path);
    foreach (['/favicon.ico', '/robots.txt', '/apple-touch-icon', '/sitemap', '/ads.txt',
              '/.well-known/', '/browserconfig.xml', '/manifest.json'] as $x) {
        if (str_contains($p, $x)) {
            return true;
        }
    }
    return false;
}

/** Almacen persistente del analisis web. */
function load_web_store(): array
{
    $f   = state_dir() . '/web_events.json';
    $raw = is_file($f) ? slurp($f, 20971520) : null;
    $d   = $raw !== null ? json_decode($raw, true) : null;
    if ($raw !== null && !is_array($d)) {
        clog('web_events.json ilegible o truncado; se reinicia el historico web');
    }
    if (!is_array($d)) {
        $d = [];
    }
    return $d + [
        'readers'   => [],   // fichero => ['inode'=>, 'offset'=>]
        'days'      => [],   // dia => contadores
        'hits'      => [],   // rutas sensibles que respondieron 200
        'ip_cats'   => [],   // ip => [categoria => n]
        'last_seen' => [],   // ip => ts
    ];
}

function save_web_store(array $store): void
{
    write_atomic(
        state_dir() . '/web_events.json',
        json_encode($store, JSON_UNESCAPED_SLASHES),
        0640
    );
}

/**
 * Ficheros de log a leer, por dominio.
 *
 * En Plesk conviven nginx delante y Apache detras. Se leen los de Apache
 * (access_ssl_log y access_log) porque son los que ven las peticiones
 * dinamicas, que es donde estan los escaneos; los .processed son la parte del
 * dia que Plesk ya ha rotado para las estadisticas y contienen el grueso.
 */
function web_log_files(): array
{
    $out = [];
    foreach (glob('/var/www/vhosts/*/logs/*', GLOB_ONLYDIR) ?: [] as $dir) {
        $dominio = basename($dir);
        foreach (['access_ssl_log', 'access_ssl_log.processed', 'access_log', 'access_log.processed'] as $n) {
            if (is_readable($dir . '/' . $n)) {
                $out[] = ['domain' => $dominio, 'file' => $dir . '/' . $n, 'kind' => 'access'];
            }
        }
        foreach (['error_log', 'error_log.processed'] as $n) {
            if (is_readable($dir . '/' . $n)) {
                $out[] = ['domain' => $dominio, 'file' => $dir . '/' . $n, 'kind' => 'error'];
            }
        }
    }
    return $out;
}

/** Reserva y devuelve el contador del dia. */
function &web_day(array &$store, string $day): array
{
    if (!isset($store['days'][$day]) || !is_array($store['days'][$day])) {
        $store['days'][$day] = [
            'suspicious' => 0, 'blocked' => 0,
            'ips' => [], 'paths' => [], 'domains' => [], 'cats' => [],
        ];
    }
    return $store['days'][$day];
}

/** Anota una peticion sospechosa. */
function web_anota(array &$store, int $ts, string $ip, string $dominio, string $ruta, string $cat, bool $bloqueada): void
{
    $day = date('Y-m-d', $ts);
    $d   = &web_day($store, $day);

    if ($bloqueada) {
        $d['blocked']++;
    } else {
        $d['suspicious']++;
    }
    $d['ips'][$ip]         = ($d['ips'][$ip] ?? 0) + 1;
    $d['domains'][$dominio] = ($d['domains'][$dominio] ?? 0) + 1;
    if ($cat !== '') {
        $d['cats'][$cat] = ($d['cats'][$cat] ?? 0) + 1;
    }
    // La ruta se guarda recortada: hay escaneos que meten cadenas larguisimas
    $corta = substr($ruta, 0, 120);
    $d['paths'][$corta] = ($d['paths'][$corta] ?? 0) + 1;
    unset($d);

    if ($cat !== '') {
        $store['ip_cats'][$ip][$cat] = ($store['ip_cats'][$ip][$cat] ?? 0) + 1;
    }
    $store['last_seen'][$ip] = max($ts, $store['last_seen'][$ip] ?? 0);
}

/** Lee la parte nueva de un fichero y la pasa linea a linea al procesador. */
function web_lee_incremental(array &$store, string $file, callable $fn, int &$restantes): void
{
    $st = @stat($file);
    if (!$st) {
        return;
    }
    $inode = (int) $st['ino'];
    $size  = (int) $st['size'];
    $prev  = $store['readers'][$file] ?? ['inode' => 0, 'offset' => 0];

    // Inodo distinto (rotacion) o fichero encogido (Plesk trunca al rotar):
    // se empieza de nuevo.
    $offset = ($prev['inode'] === $inode && (int) $prev['offset'] <= $size) ? (int) $prev['offset'] : 0;
    if ($offset === $size) {
        $store['readers'][$file] = ['inode' => $inode, 'offset' => $offset];
        return;
    }
    // Primera pasada sobre un fichero grande: solo la cola.
    if ($offset === 0 && $size > CENT_WEB_MAX_BYTES) {
        $offset = $size - CENT_WEB_MAX_BYTES;
    }

    $fh = @fopen($file, 'rb');
    if (!$fh) {
        return;
    }
    fseek($fh, $offset);
    if ($offset > 0) {
        fgets($fh);   // descartamos la linea partida
    }
    while ($restantes > 0 && ($line = fgets($fh)) !== false) {
        $restantes--;
        $fn(rtrim($line, "\r\n"));
    }
    $store['readers'][$file] = ['inode' => $inode, 'offset' => ftell($fh)];
    fclose($fh);
}

/**
 * IPs cuyas peticiones no cuentan como escaneo: las del propio servidor (los
 * escaneos de Centinela y los scripts de la casa salen con ellas) y las de
 * confianza del guard (allow_ips de ssh_guard.json). Un 200 sobre una ruta
 * sensible SI se registra venga de donde venga: que lo encuentre uno mismo es
 * la mejor noticia posible, pero sigue siendo algo que se sirvio.
 */
function web_ips_confianza(): array
{
    static $lista = null;
    if ($lista !== null) {
        return $lista;
    }
    $lista = ['127.0.0.0/8', '::1'];
    $propias = trim((string) @shell_exec('hostname -I 2>/dev/null'));
    foreach (preg_split('/\s+/', $propias) ?: [] as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $lista[] = $ip;
        }
    }
    if (function_exists('guard_policy')) {
        foreach ((array) (guard_policy()['allow_ips'] ?? []) as $cidr) {
            $lista[] = (string) $cidr;
        }
    }
    return $lista;
}

function web_ip_confianza(string $ip): bool
{
    if (function_exists('guard_ip_in_list')) {
        return guard_ip_in_list($ip, web_ips_confianza());
    }
    return in_array($ip, web_ips_confianza(), true);
}

const CENT_WEB_RECHECK_TTL = 1800;   // cada acierto se recomprueba como mucho cada media hora
const CENT_WEB_RECHECK_MAX = 20;     // URLs por pasada

/** Codigo HTTP que devuelve hoy una URL (0 si no se pudo comprobar). Sin seguir redirecciones. */
function web_estado_en_vivo(string $url): int
{
    $ctx = stream_context_create([
        'http' => ['method' => 'GET', 'timeout' => 5, 'ignore_errors' => true, 'follow_location' => 0,
                   'user_agent' => 'Centinela-recheck/1.0', 'header' => "Range: bytes=0-0\r\n"],
        'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
    ]);
    $fh = @fopen($url, 'rb', false, $ctx);
    if (!$fh) {
        return 0;
    }
    $meta = stream_get_meta_data($fh);
    fclose($fh);
    $estado = 0;
    foreach ((array) ($meta['wrapper_data'] ?? []) as $hdr) {
        if (is_string($hdr) && preg_match('~^HTTP/\S+ (\d{3})~', $hdr, $m)) {
            $estado = (int) $m[1];
        }
    }
    return $estado;
}

/**
 * Vuelve a pedir en vivo cada ruta sensible que respondio 200. Un acierto que
 * hoy devuelve 403/404 esta corregido: se sigue mostrando mientras dure la
 * ventana (hubo fuga y hay que rotar lo que contuviera) pero deja de ser
 * critico. Un fallo de red se anota como 0, «sin comprobar», nunca como corregido.
 */
function web_recomprueba_hits(array &$store): void
{
    $ahora     = time();
    $pendiente = [];
    foreach ($store['hits'] as $h) {
        $dom = (string) ($h['domain'] ?? '');
        if ($dom === '' || $dom[0] === '_' || !preg_match('/^[A-Za-z0-9.-]+$/', $dom)) {
            continue;
        }
        if ((int) ($h['checked'] ?? 0) > $ahora - CENT_WEB_RECHECK_TTL) {
            continue;
        }
        $pendiente[$dom . (string) ($h['path'] ?? '')] = $dom;
    }
    $resultado = [];
    foreach (array_slice($pendiente, 0, CENT_WEB_RECHECK_MAX, true) as $clave => $dom) {
        $ruta = substr($clave, strlen($dom));
        $resultado[$clave] = web_estado_en_vivo('https://' . $dom . $ruta);
    }
    if (!$resultado) {
        return;
    }
    foreach ($store['hits'] as $i => $h) {
        $clave = (string) ($h['domain'] ?? '') . (string) ($h['path'] ?? '');
        if (array_key_exists($clave, $resultado)) {
            $store['hits'][$i]['now']     = $resultado[$clave];
            $store['hits'][$i]['checked'] = $ahora;
        }
    }
}

/** Un acierto sigue abierto si hoy responde 2xx o no se ha podido comprobar. */
function web_hit_abierto(array $h): bool
{
    $now = (int) ($h['now'] ?? 0);
    return $now === 0 || ($now >= 200 && $now < 300);
}

/** Procesa una linea de log de acceso en formato combinado. */
function web_ingest_access(array &$store, string $dominio, string $line): void
{
    // Filtro barato antes de gastar una expresion regular: la inmensa mayoria
    // de las lineas son trafico normal y no hace falta ni interpretarlas.
    if ($line === '' || (!str_contains($line, '" 4') && !str_contains($line, '" 5')
        && !str_contains($line, '.env') && !str_contains($line, '.git')
        && !str_contains($line, 'wp-login') && !str_contains($line, 'xmlrpc')
        && !str_contains($line, 'phpmyadmin') && !str_contains($line, 'vendor/'))) {
        return;
    }

    if (!preg_match('~^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*?) [^"]*" (\d{3}) ~', $line, $m)) {
        return;
    }
    [$todo, $ip, $fecha, $metodo, $ruta, $estado] = $m;
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return;
    }

    $ts = strtotime(str_replace(':', ' ', substr($fecha, 0, 11)) . substr($fecha, 11));
    if (!$ts || $ts > time() + 86400) {
        $ts = time();
    }
    $estado = (int) $estado;
    $cat    = web_path_category($ruta);

    // Sin categoria, solo interesan los errores que no son ruido de fondo.
    if ($cat === '') {
        if (!in_array($estado, [401, 403, 404], true) || web_ruido($ruta)) {
            return;
        }
        $cat = 'escaneo';
    }

    // El propio servidor y las IPs de confianza no son escaneres: no inflan las
    // estadisticas. Sus aciertos (abajo) si se guardan.
    if (!web_ip_confianza($ip)) {
        web_anota($store, $ts, $ip, $dominio, $ruta, $cat, false);
    }

    // Lo importante: una ruta que no deberia existir ha respondido que si.
    if (in_array($cat, ['secreto', 'copia', 'ejecucion'], true) && $estado >= 200 && $estado < 300) {
        $store['hits'][] = [
            'ts' => $ts, 'ip' => $ip, 'domain' => $dominio,
            'path' => substr($ruta, 0, 160), 'status' => $estado, 'cat' => $cat,
            'method' => substr($metodo, 0, 10),
        ];
        if (count($store['hits']) > 200) {
            $store['hits'] = array_slice($store['hits'], -200);
        }
    }
}

/** Procesa una linea del error_log buscando denegaciones de ModSecurity. */
function web_ingest_error(array &$store, string $dominio, string $line): void
{
    if (!str_contains($line, 'ModSecurity: Access denied')) {
        return;
    }
    if (!preg_match('/\[client ([^\]\s]+)/', $line, $mi)) {
        return;
    }
    // Apache escribe «[client 1.2.3.4:0]»: el puerto va pegado a la direccion.
    // Se prueba entera primero, que en IPv6 los dos puntos son parte de ella.
    $ip = $mi[1];
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $sinPuerto = preg_replace('/:\d+$/', '', $ip);
        if (filter_var($sinPuerto, FILTER_VALIDATE_IP)) {
            $ip = $sinPuerto;
        }
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return;
    }
    $ruta = '';
    if (preg_match('/\[uri "([^"]*)"/', $line, $mu)) {
        $ruta = $mu[1];
    }
    $ts = time();
    if (preg_match('/^\[[A-Za-z]{3} ([A-Za-z]{3} \d{1,2}) ([\d:]{8})\.\d+ (\d{4})\]/', $line, $mt)) {
        $t = strtotime("{$mt[1]} {$mt[3]} {$mt[2]}");
        if ($t) {
            $ts = $t;
        }
    }

    $cat = web_path_category($ruta) ?: 'bloqueado';
    web_anota($store, $ts, $ip, $dominio, $ruta, $cat, true);
}

/** Descarta lo que cae fuera de la ventana de historico. */
function prune_web_store(array &$store): void
{
    $corte = date('Y-m-d', time() - CENT_WEB_DAYS * 86400);
    foreach (array_keys($store['days']) as $day) {
        if ((string) $day < $corte) {
            unset($store['days'][$day]);
        }
    }
    ksort($store['days']);

    foreach ($store['days'] as &$d) {
        foreach (['ips' => 2000, 'paths' => 500, 'domains' => 200] as $k => $tope) {
            if (isset($d[$k]) && count($d[$k]) > $tope) {
                arsort($d[$k]);
                $d[$k] = array_slice($d[$k], 0, $tope, true);
            }
        }
    }
    unset($d);

    $tsCorte = time() - CENT_WEB_DAYS * 86400;
    $store['hits']      = array_values(array_filter($store['hits'], fn($h) => $h['ts'] >= $tsCorte));
    $store['last_seen'] = array_filter($store['last_seen'], fn($t) => $t >= $tsCorte);
    if (count($store['last_seen']) > 20000) {
        arsort($store['last_seen']);
        $store['last_seen'] = array_slice($store['last_seen'], 0, 20000, true);
    }
    // ip_cats solo se conserva para las IPs que siguen en la ventana
    $store['ip_cats'] = array_intersect_key($store['ip_cats'], $store['last_seen']);

    // Los lectores de ficheros que ya no existen sobran
    foreach (array_keys($store['readers']) as $f) {
        if (!is_file((string) $f)) {
            unset($store['readers'][$f]);
        }
    }
}

/** Recoge y analiza los logs web de todos los dominios. */
function collect_web(): array
{
    $store     = load_web_store();
    $restantes = CENT_WEB_MAX_LINES;

    foreach (web_log_files() as $entrada) {
        $dominio = $entrada['domain'];
        $fn = $entrada['kind'] === 'access'
            ? function (string $l) use (&$store, $dominio) { web_ingest_access($store, $dominio, $l); }
            : function (string $l) use (&$store, $dominio) { web_ingest_error($store, $dominio, $l); };
        web_lee_incremental($store, $entrada['file'], $fn, $restantes);
        if ($restantes <= 0) {
            clog('analisis web: alcanzado el tope de lineas por pasada');
            break;
        }
    }

    prune_web_store($store);
    web_recomprueba_hits($store);
    save_web_store($store);

    return build_web_report($store);
}

/** Construye el informe que consume el panel. */
function build_web_report(array $store): array
{
    $days = $store['days'];
    $desde = date('Y-m-d', time() - CENT_WEB_DAYS * 86400);

    $serie = [];
    for ($i = CENT_WEB_DAYS - 1; $i >= 0; $i--) {
        $d = date('Y-m-d', time() - $i * 86400);
        $serie[] = [
            'date'    => $d,
            'count'   => (int) ($days[$d]['suspicious'] ?? 0),
            'blocked' => (int) ($days[$d]['blocked'] ?? 0),
        ];
    }

    $ips = $paths = $domains = $cats = [];
    $totalSusp = $totalBloq = 0;
    foreach ($days as $day => $d) {
        if ((string) $day < $desde) {
            continue;
        }
        $totalSusp += (int) ($d['suspicious'] ?? 0);
        $totalBloq += (int) ($d['blocked'] ?? 0);
        foreach (($d['ips'] ?? []) as $ip => $n)     { $ips[$ip] = ($ips[$ip] ?? 0) + $n; }
        foreach (($d['paths'] ?? []) as $p => $n)    { $paths[$p] = ($paths[$p] ?? 0) + $n; }
        foreach (($d['domains'] ?? []) as $x => $n)  { $domains[$x] = ($domains[$x] ?? 0) + $n; }
        foreach (($d['cats'] ?? []) as $c => $n)     { $cats[$c] = ($cats[$c] ?? 0) + $n; }
    }
    arsort($ips);
    arsort($paths);
    arsort($domains);
    arsort($cats);

    $topIps = [];
    foreach (array_slice($ips, 0, 25, true) as $ip => $n) {
        $topIps[] = [
            'ip'        => $ip,
            'count'     => $n,
            'cats'      => $store['ip_cats'][$ip] ?? [],
            'last_seen' => $store['last_seen'][$ip] ?? null,
        ];
    }

    $hits       = array_slice(array_reverse($store['hits']), 0, 25);
    $abiertos   = array_values(array_filter($hits, 'web_hit_abierto'));
    $corregidos = array_values(array_filter($hits, fn($h) => !web_hit_abierto($h)));

    $findings = [];

    // 1. Lo mas grave: algo que no deberia estar publicado ha respondido 200 y sigue haciendolo.
    if ($abiertos) {
        $muestra = array_slice($abiertos, 0, 4);
        $detalle = implode('; ', array_map(
            fn($h) => $h['domain'] . $h['path'] . ' (' . $h['status'] . ' a ' . $h['ip'] . ')',
            $muestra
        ));
        $findings[] = finding(
            'web.exposed',
            SEV_CRIT,
            count($abiertos) . ' peticion(es) a ficheros sensibles que respondieron 200',
            $detalle . '. Un escaneo automatico ha encontrado algo servido que no deberia estarlo.',
            'Retirar el fichero del docroot y rotar cualquier credencial que contuviera',
            guide(
                'Los escaneos que buscan .env, .git o copias de seguridad son constantes y automaticos. Que uno '
                . 'reciba un 200 significa que se ha llevado el contenido: a partir de ahi, las credenciales que '
                . 'hubiera dentro hay que darlas por publicas.',
                [
                    ['do' => 'Mira que se sirvio exactamente y desde cuando',
                     'cmd' => 'grep -h ' . escapeshellarg((string) ($muestra[0]['path'] ?? '')) . ' /var/www/vhosts/*/logs/*/access_ssl_log* | tail -20'],
                    ['do' => 'Saca el fichero del docroot; no basta con renombrarlo',
                     'cmd' => 'ls -la /var/www/vhosts/' . escapeshellarg((string) ($muestra[0]['domain'] ?? 'DOMINIO')) . '/httpdocs/' . ltrim((string) ($muestra[0]['path'] ?? ''), '/')],
                    ['do' => 'Rota todo lo que hubiera dentro: contrasenas de base de datos, claves de API, '
                           . 'tokens. Cambiarlas es lo unico que revierte la fuga.'],
                    ['do' => 'Bloquea en el servidor web el acceso a ficheros ocultos y copias, para que el '
                           . 'proximo despiste no se sirva',
                     'cmd' => 'printf \'<FilesMatch "^\\\\.|\\\\.(bak|old|save|sql|swp)$">\\n  Require all denied\\n</FilesMatch>\\n\' >> /var/www/vhosts/DOMINIO/conf/vhost.conf && plesk sbin httpdmng --reconfigure-domain DOMINIO'],
                    ['do' => 'Revisa si esa IP hizo algo mas despues de encontrarlo',
                     'cmd' => 'grep -h ' . escapeshellarg((string) ($muestra[0]['ip'] ?? '')) . ' /var/www/vhosts/*/logs/*/access_ssl_log* | tail -40'],
                ],
                'curl -s -o /dev/null -w "%{http_code}\\n" https://DOMINIO' . ((string) ($muestra[0]['path'] ?? '')),
                'Si el fichero era un .env o un wp-config, considera comprometidas tambien la base de datos y '
                . 'las cuentas de correo que aparecieran en el.'
            )
        );
    }

    // 1b. Aciertos ya corregidos: la ruta hoy no responde 200. Se avisa (hubo fuga,
    //     conviene rotar lo que contuviera) pero no penaliza: lo que habia que hacer
    //     ya esta hecho. Desaparece solo al salir de la ventana.
    if ($corregidos && !$abiertos) {
        $muestra = array_slice($corregidos, 0, 4);
        $findings[] = finding(
            'web.exposed_fixed',
            SEV_INFO,
            count($corregidos) . ' peticion(es) a ficheros sensibles respondieron 200; ya no se sirven',
            implode('; ', array_map(
                fn($h) => $h['domain'] . $h['path'] . ' (200 a ' . $h['ip'] . ', hoy ' . (int) $h['now'] . ')',
                $muestra
            )) . '. Comprobado en vivo: la ruta ya no responde 200.',
            'Si el fichero contenia credenciales, rotarlas: cerrar la ruta no deshace lo que ya se sirvio',
            guide(
                'Que la ruta ya no se sirva evita fugas nuevas, pero no recupera lo que un escaneo pudo '
                . 'llevarse mientras respondia 200. Si las IPs que lo pidieron son tuyas o del propio '
                . 'servidor, no hubo fuga. El aviso se retira solo al salir de la ventana de '
                . CENT_WEB_DAYS . ' dias.',
                [
                    ['do' => 'Mira quien lo pidio y cuando',
                     'cmd' => 'grep -h ' . escapeshellarg((string) ($muestra[0]['path'] ?? '')) . ' /var/www/vhosts/*/logs/*/access_ssl_log* | tail -20'],
                    ['do' => 'Si el contenido llevaba contrasenas, claves o tokens, cambialos.'],
                ],
                'curl -s -o /dev/null -w "%{http_code}\\n" https://' . (string) ($muestra[0]['domain'] ?? 'DOMINIO') . (string) ($muestra[0]['path'] ?? '')
            )
        );
    }

    // 2. IPs que se dedican a escanear.
    $escaneando = array_values(array_filter($topIps, fn($x) => $x['count'] >= CENT_WEB_SCAN_MIN));
    if ($escaneando) {
        $lista = array_slice($escaneando, 0, 5);
        $findings[] = finding(
            'web.scan',
            SEV_WARN,
            count($escaneando) . ' IP(s) escaneando los sitios alojados',
            implode(', ', array_map(
                fn($x) => $x['ip'] . ' (' . number_format((int) $x['count'], 0, ',', '.') . ' peticiones)',
                $lista
            )) . '. Buscan ficheros de configuracion, paneles y rutas de exploits conocidos.',
            'Bloquearlas desde el panel si el volumen molesta; lo importante es que no encuentren nada',
            guide(
                'El escaneo en si es ruido de fondo de internet y no se puede evitar. Importa por dos motivos: '
                . 'consume recursos, y sirve de aviso de que alguien esta buscando activamente un hueco en tus '
                . 'sitios. Lo que hay que garantizar es que no haya nada que encontrar.',
                [
                    ['do' => 'Mira que estan buscando, que dice mucho de contra que van',
                     'cmd' => 'grep -h ' . escapeshellarg((string) ($lista[0]['ip'] ?? '')) . ' /var/www/vhosts/*/logs/*/access_ssl_log* | awk \'{print $7}\' | sort | uniq -c | sort -rn | head -20'],
                    ['do' => 'Comprueba que ninguna de esas rutas responde 200 (la tabla de arriba lo dice, pero '
                           . 'conviene verlo en vivo)',
                     'cmd' => 'curl -s -o /dev/null -w "%{http_code}\\n" https://DOMINIO/.env'],
                    ['do' => 'Bloquealas desde la tabla de ataques web con el boton Bloquear, o a mano',
                     'cmd' => 'fail2ban-client set plesk-permanent-ban banip ' . ((string) ($lista[0]['ip'] ?? 'IP'))],
                    ['do' => 'Si ModSecurity esta en modo deteccion, pasalo a bloqueo: casi todo esto lo para solo.'],
                ],
                'grep -c ' . escapeshellarg((string) ($lista[0]['ip'] ?? '')) . ' /var/www/vhosts/*/logs/*/access_ssl_log'
            )
        );
    }

    // 3. Fuerza bruta contra WordPress.
    $wp = 0;
    foreach ($store['ip_cats'] as $c) {
        $wp += (int) ($c['wordpress'] ?? 0);
    }
    if ($wp >= CENT_WEB_WP_MIN) {
        $peores = [];
        foreach ($store['ip_cats'] as $ip => $c) {
            if (($c['wordpress'] ?? 0) > 0) {
                $peores[$ip] = $c['wordpress'];
            }
        }
        arsort($peores);
        $findings[] = finding(
            'web.wpbrute',
            SEV_WARN,
            'Fuerza bruta contra WordPress: ' . number_format($wp, 0, ',', '.') . ' peticiones',
            'Desde ' . count($peores) . ' IP(s). Las mas activas: '
                . implode(', ', array_map(
                    fn($ip, $n) => $ip . ' (' . $n . ')',
                    array_slice(array_keys($peores), 0, 3),
                    array_slice(array_values($peores), 0, 3)
                )),
            'Activar el jail plesk-wordpress y limitar el acceso a wp-login.php',
            guide(
                'wp-login.php y xmlrpc.php son el objetivo mas atacado de internet. Basta una contrasena floja '
                . 'en un solo usuario para que el sitio caiga, y desde ahi se llega al resto de la suscripcion.',
                [
                    ['do' => 'Comprueba que el jail de WordPress esta activo y cogiendolos',
                     'cmd' => 'fail2ban-client status plesk-wordpress'],
                    ['do' => 'Si xmlrpc.php no lo usa nadie (ni Jetpack ni la app movil), cierralo del todo',
                     'cmd' => 'printf \'<Files "xmlrpc.php">\\n  Require all denied\\n</Files>\\n\' >> /var/www/vhosts/DOMINIO/conf/vhost.conf && plesk sbin httpdmng --reconfigure-domain DOMINIO'],
                    ['do' => 'Instala el WordPress Toolkit de Plesk y activa sus medidas de seguridad, que incluyen '
                           . 'limitar los intentos de acceso.'],
                    ['do' => 'Revisa que ningun usuario del sitio use una contrasena debil, empezando por admin.'],
                ],
                'fail2ban-client status plesk-wordpress'
            )
        );
    }

    return [
        'window_days'  => CENT_WEB_DAYS,
        'suspicious'   => $totalSusp,
        'blocked'      => $totalBloq,
        'series_daily' => $serie,
        'top_ips'      => $topIps,
        'top_paths'    => array_map(
            fn($p, $n) => ['path' => $p, 'count' => $n],
            array_keys(array_slice($paths, 0, 20, true)),
            array_values(array_slice($paths, 0, 20, true))
        ),
        'by_domain'    => array_map(
            fn($d, $n) => ['domain' => $d, 'count' => $n],
            array_keys(array_slice($domains, 0, 10, true)),
            array_values(array_slice($domains, 0, 10, true))
        ),
        'by_cat'       => $cats,
        'hits'         => $hits,
        'findings'     => $findings,
    ];
}
