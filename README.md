# Centinela

Panel de seguridad en tiempo real para servidores Linux: estado de salud,
análisis de ataques, looking glass, alertas por correo e informe semanal
automático al administrador.

Funciona en servidores con **Plesk Obsidian**, con **HestiaCP** y **sin
panel** (Ubuntu/Debian o AlmaLinux/RHEL con nginx o Apache, PHP-FPM y los
servicios instalados a mano). Se actualiza solo desde GitHub en toda la flota.

---

## Qué hace

| | |
|---|---|
| **Salud global** | Nota de 0 a 100 a partir de comprobaciones ponderadas, con tendencia de 30 días |
| **Incidencias** | Cada hallazgo con su gravedad, su explicación y una guía de solución con los pasos, sus comandos y cómo verificar que ha quedado arreglado |
| **Recomprobar** | Botón en cada incidencia que fuerza una recogida nueva y dice si sigue presente o ya está resuelta |
| **Bloqueo** | Cada IP atacante muestra si algún jail de fail2ban la retiene, y se bloquea o desbloquea desde el propio panel |
| **Ataques** | Intentos fallidos por día y hora, IPs de origen con ASN, operador y país, usuarios más probados y accesos correctos recientes |
| **Ataques web** | Escaneos contra los sitios alojados: rutas buscadas, quién las busca, qué ha bloqueado ModSecurity y —lo importante— si alguna respondió 200 |
| **Defensas** | Estado de fail2ban por jail, cortafuegos, endurecimiento de SSH, ModSecurity, Imunify y antivirus |
| **Sistema** | Kernel, reinicio pendiente, actualizaciones (separando las de seguridad), servicios, discos, puertos expuestos y certificados |
| **Correo** | PTR y coincidencia directa-inversa, SPF, DKIM, DMARC, cola y rebotes |
| **Looking glass** | 21 herramientas de diagnóstico de red y seguridad, públicas y con resultados estructurados |
| **Avisos** | Correo cuando aparece una incidencia nueva, e informe semanal completo siempre |
| **Modo incidente** | Un vigilante pasa cada minuto por los módulos baratos y avisa de lo crítico sin esperar al ciclo del colector |
| **Geo-valla** | Política de origen para SSH y el panel: países y rangos permitidos; lo demás se banea al primer intento fallido |
| **Syslog remoto** | Exporta salud, ataques y transiciones de incidencias a un SIEM en RFC 5424 con cuerpo clave=valor |

---

## El looking glass

Página pública e independiente del panel: no expone ningún dato interno del
servidor, solo ejecuta comprobaciones contra el destino que se le indique.

### Conectividad

| Herramienta | Qué devuelve |
|---|---|
| **Ping** | Latencia media, mínima, máxima, variación y pérdida, con lectura de si la ruta es estable |
| **Traceroute** | Ruta salto a salto con mtr si está disponible, y recuento de saltos sin respuesta |
| **Puertos abiertos** | Sondeo en paralelo de 21 puertos habituales, señalando los que no deberían estar expuestos |
| **Puerto concreto** | Estado de un puerto TCP, tiempo de conexión y anuncio del servicio si lo hay |
| **MTU de la ruta** | Mayor paquete que llega sin fragmentar, por búsqueda binaria con el bit DF; detecta túneles y PPPoE en el camino |
| **Latencia global** | Ping desde sondas reales en seis continentes (globalping.io): distingue una caída del servidor de un fallo de enrutado que solo afecta a una región |

### Nombres

| Herramienta | Qué devuelve |
|---|---|
| **Consulta DNS** | Registros por tipo, incluidos DS y DNSKEY, con sección de autoridad |
| **DNS inverso** | Registro PTR y validación directa-inversa, la causa más común de rechazo de correo |
| **RDAP / WHOIS** | Titular, registrador, fechas, estado, servidores de nombres y contacto de abuso |
| **ASN y enrutado** | Sistema autónomo, operador, prefijo anunciado y aviso si el prefijo tiene varios orígenes |
| **Mapa BGP** | Dónde anuncia sus rutas un ASN, sobre un mapa mundial interactivo: puntos por ciudad con sus prefijos, zoom y arrastre, fichas por país, visibilidad RIS y vecinos de tránsito. Acepta AS3352, una IP o un dominio |
| **Propagación DNS** | El mismo registro consultado en 8 resolutores públicos a la vez, con detección de consenso y discrepancias |

### Seguridad

| Herramienta | Qué devuelve |
|---|---|
| **Certificado TLS** | Cadena completa, caducidad, nombres cubiertos, protocolo y cifrado negociados, y si el certificado cubre el nombre consultado |
| **Cabeceras HTTP** | Nota de A a F sobre seis cabeceras de seguridad, más las que revelan la tecnología del servidor |
| **Listas negras** | Reputación en diez listas antispam, sondeando antes cuáles responden de verdad desde este servidor |
| **Correo del dominio** | MX, SPF, DKIM y DMARC con diagnóstico de la política y nota sobre cuatro |
| **Reputación IP** | Veredicto agregado: historial de ataques visto por los sensores de SANS ISC y blocklist.de, pertenencia a Spamhaus DROP, botnets C2 de Feodo Tracker, salidas de Tor, historial de enrutado del prefijo y contacto de abuso al que reportar |
| **DNSSEC** | Valida la cadena de firmas de la raíz al dominio y señala dónde se rompe (sin firmar, sin anclar en el padre, o bogus) |
| **Certificados emitidos** | Historial de Certificate Transparency (crt.sh): todo cert emitido para el dominio, subdominios que revela y cuáles ya no resuelven (candidatos a takeover) |
| **Entrega SMTP** | Conexión real a cada MX: saludo, capacidades EHLO, STARTTLS, certificado con validación de nombre, y anclaje DANE/TLSA |
| **Análisis de servidor** | Identifica servidor web, panel (cPanel/Plesk/Hestia/DirectAdmin/Webmin), CMS (WordPress/Joomla/Drupal…) y versión; marca versiones sin soporte (endoflife.date) y lista CVE conocidos (CIRCL) |

Los resultados se presentan en tarjetas estructuradas con indicadores de
estado, y la salida cruda queda siempre accesible debajo. El historial de la
sesión vive solo en el navegador del visitante.

### Sobre la comprobación de listas negras

Consultar una DNSBL tiene dos trampas que producen resultados falsos:

1. **Los códigos `127.255.255.x` no son listados**, sino mensajes de la propia
   lista. Spamhaus devuelve `127.255.255.254` cuando la consulta llega desde un
   resolver público — y como casi todos los servidores resuelven vía 1.1.1.1 u
   8.8.8.8, eso daría positivo en **todas** las direcciones, incluidas las de
   Google. Es un error muy extendido en herramientas de este tipo.
2. **No todas las listas responden desde cualquier origen**, y algunas han
   cerrado. Dar «limpia» por una lista que no contesta engaña tanto como un
   falso positivo.

Centinela sondea cada lista con las entradas de prueba universales
(`127.0.0.2` debe salir listada, `127.0.0.1` nunca), probando primero un
resolver recursivo local y después el del sistema. Se queda con el que dé
respuestas coherentes, cachea esa decisión seis horas, y las listas que no
superan el sondeo se informan aparte como **no consultables** en lugar de
contarlas como limpias. La nota final solo tiene en cuenta las que realmente
se pudieron consultar.

### El mapa BGP por dentro

Los datos salen de RIPEstat (RIPE NCC): geolocalización MaxMind GeoLite de
cada prefijo anunciado, estado de enrutado y vecinos, cacheados media hora por
ASN para no castigar un servicio público. El mapa base es Natural Earth 1:110m
(dominio público) convertido a SVG propio (`assets/worldmap.js`, 119 KB, 175
países): la CSP de esta página no permite CDNs ni teselas externas, así que
todo es local y se carga solo la primera vez que alguien usa la herramienta.
La interacción (zoom con rueda, arrastre, tooltips por punto, fichas por país
que resaltan y centran) es SVG y DOM a mano, sin ninguna librería.

La geolocalización de prefijos sitúa el registro, no necesariamente el
tráfico; el propio mapa lo advierte.

### Por qué es seguro exponerlo

Es la única superficie que recibe entrada del usuario, así que concentra las
defensas:

1. **Catálogo cerrado.** El usuario elige una clave de una lista; nunca escribe
   un binario ni una opción.
2. **Sin shell.** `proc_open` recibe un array de argumentos, de modo que no hay
   interpretación de metacaracteres.
3. **Resolución previa.** El destino se valida por sintaxis, se resuelve, y se
   comprueba que **todas** sus direcciones son públicas antes de conectar.
   Después se conecta contra la IP validada y no contra el nombre, lo que cierra
   la puerta a que un dominio reapunte a la red interna entre la comprobación y
   la conexión.
4. **Rangos internos bloqueados.** Privadas, loopback, enlace local, CGNAT y
   documentación, tanto en IPv4 como en IPv6.
5. **Contención.** Tiempo de espera por herramienta, salida truncada, límite por
   minuto y por hora, y verificación en la primera consulta.
6. **Salida tratada como hostil.** El cliente construye el DOM con `textContent`;
   nada de lo que devuelve un servidor remoto se interpreta como marcado.

Para dejarlo tras el login basta con `'public' => false` en la configuración, o
instalar con `--private-lg`.

---

## Instalación

Guía paso a paso, con requisitos por plataforma y puesta en marcha:
[docs/INSTALACION.md](docs/INSTALACION.md).

```bash
git clone https://github.com/USUARIO/centinela.git && cd centinela
./install.sh --domain seguridad.midominio.com --email admin@midominio.com
```

El instalador detecta la plataforma, crea el sitio del panel, publica la
interfaz, deja el colector como servicio de systemd, amplía `open_basedir`,
emite el certificado Let's Encrypt y pide las credenciales. Lo que cambia
según dónde se instale:

| Plataforma | Cómo se detecta | Dónde publica el panel | Certificado | Jail de bloqueos |
|---|---|---|---|---|
| **Plesk** | binario `plesk` | subdominio de Plesk (usuario del vhost, `open_basedir` ampliado) | extensión Let's Encrypt | `plesk-permanent-ban` |
| **HestiaCP** | `/usr/local/hestia` | dominio web del usuario `admin` (`--hestia-user` para otro), con una plantilla PHP-FPM derivada que amplía `open_basedir` | `v-add-letsencrypt-domain` | `centinela` (lo crea el instalador) |
| **Sin panel** | ninguna de las anteriores | vhost propio de nginx o Apache en `/var/www/centinela`, pool PHP-FPM dedicado que corre como `centinela-web` | `certbot`, si está instalado | `centinela` (lo crea el instalador) |

Sin panel hacen falta `php-cli`, `php-fpm` y nginx o Apache ya instalados; el
instalador dice exactamente qué falta. Con `--platform` se fuerza la
plataforma si la detección no acierta, y con `--webserver nginx|apache` el
servidor web a usar cuando conviven los dos.

### Opciones

| Opción | Efecto |
|---|---|
| `--domain DOMINIO` | Subdominio del panel (obligatorio) |
| `--email DIRECCIÓN` | Administrador que recibe avisos e informe (obligatorio) |
| `--interval TIEMPO` | Frecuencia de recogida, por defecto `5min` |
| `--weekly-day DÍA` | Día del informe: `Mon`…`Sun`, por defecto `Mon` |
| `--weekly-hour HORA` | Hora del informe, por defecto `08` |
| `--platform TIPO` | `plesk`, `hestia` o `generic`; por defecto se detecta |
| `--hestia-user USUARIO` | Usuario de Hestia que aloja el panel (por defecto `admin`) |
| `--webserver TIPO` | Sin panel: `nginx` o `apache`; por defecto el que esté activo |
| `--update-repo REPO` | Repositorio `usuario/centinela` del que actualizarse solo |
| `--update-mode MODO` | `auto`, `patch` o `notify` (por defecto `notify`) |
| `--private-lg` | El looking glass exige inicio de sesión |
| `--skip-ssl` | No emitir certificado |
| `-y`, `--yes` | Sin confirmación interactiva |
| `--upgrade` | Actualiza el código conservando la configuración |
| `--uninstall` | Desinstala (conserva configuración y datos) |

### Requisitos

systemd, PHP 8.1 o superior (en Plesk usa el suyo; en el resto el del
sistema), `dig`, y un MTA local (`sendmail`) para los avisos. En Plesk y
Hestia todo eso viene de serie; sin panel, además, nginx o Apache con PHP-FPM.

### Actualización automática en toda la flota

Cada servidor consulta una vez al día las *releases* del repositorio
configurado. Si hay una versión nueva la descarga, verifica el `SHA256SUMS`
de la release, hace copia del código y de la web, aplica con
`install.sh --upgrade`, comprueba que el colector sigue funcionando y, si
algo falla, **revierte** solo.

```bash
centinela-admin update --repo USUARIO/centinela --mode auto   # aplica todo
centinela-admin update --mode patch                           # solo 1.x.y -> 1.x.z
centinela-admin update --mode notify                          # solo avisa en el panel
centinela-admin update --now                                  # comprobar ahora
```

Publicar una versión es etiquetar: `git tag v1.2.0 && git push origin v1.2.0`.
El workflow de GitHub Actions comprueba la sintaxis, empaqueta y crea la
release con su checksum; en las horas siguientes toda la flota la aplica.

---

## Arquitectura

El principio que sostiene el diseño: **la interfaz web nunca ejecuta nada
privilegiado.**

```
  ┌──────────────────────────────┐
  │  centinela-collect  (root)   │   systemd timer, cada 5 min
  │  lee fail2ban, iptables,     │
  │  logs, Plesk, certificados…  │
  └──────────────┬───────────────┘
                 │ escribe
                 ▼
        /var/lib/centinela/state.json      root:centinela 0640
                 │
                 │ lee (solo lectura)
                 ▼
  ┌──────────────────────────────┐
  │  interfaz web (usuario web)  │   panel + API + looking glass
  └──────────────────────────────┘
```

El código que corre como root vive en `/usr/local/centinela`, propiedad de
root y fuera del espacio web: si un sitio alojado se viera comprometido, no
podría modificar lo que luego se ejecuta con privilegios.

### La capa de plataforma

Todo lo que depende del panel de hosting pasa por `lib/platform.php`, y el
resto del colector no sabe dónde corre. La capa responde a pocas preguntas:

| Pregunta | Plesk | HestiaCP | Sin panel |
|---|---|---|---|
| Logs web a leer | `/var/www/vhosts/*/logs/*/access_ssl_log` y `.processed` | `/var/log/apache2/domains/*.log` (o nginx) | `/var/log/{nginx,apache2}/*access*.log`, más `web.logs` de la configuración |
| Dominios alojados | base de datos `psa` | `v-list-web-domains` por usuario | `apache2ctl -S` y bloques `server` de `nginx -T` |
| Dominios de correo | tabla `mail` de `psa` | `v-list-mail-domains` | `postconf` (`mydomain`, `virtual_*_domains`) |
| Selector DKIM | `default` | `mail` | varios habituales |
| Certificados | `/usr/local/psa/var/certificates` | `/home/*/conf/web/*/ssl/*.crt` | `/etc/letsencrypt/live/*/cert.pem`, más `certs.paths` |
| Versiones de PHP | `plesk bin php_handler --list` | intérpretes instalados | intérpretes instalados |
| Jail de bloqueos | `plesk-permanent-ban` | `centinela` | `centinela` |
| Panel y su versión | módulo `plesk` | `hestia.conf` + `v-list-sys-hestia-updates` | — |

Las guías de solución también se adaptan: el mismo hallazgo da el comando de
Plesk, el de Hestia o el genérico según el servidor. Añadir una plataforma es
añadir un caso a cada función de esa capa.

Módulos específicos de un panel (`plesk.update`, `panel.update`) solo
aparecen donde ese panel existe; los demás (SSH, fail2ban, cortafuegos,
puertos, actualizaciones, cuentas, ataques, correo saliente, geo-valla,
vigilante) son iguales en todas partes.

| Ruta | Contenido |
|---|---|
| `/usr/local/centinela/` | Código privilegiado (root:root) |
| `/etc/centinela/config.php` | Configuración y credenciales (root:centinela 0640) |
| `/var/lib/centinela/` | Estado, histórico, sesiones y contadores |
| Docroot del subdominio | Interfaz web (usuario del dominio) |

### Recomprobar una incidencia

El panel no puede medir nada por sí mismo, así que el botón **Volver a
comprobar** no ejecuta la comprobación: deja una señal en
`/var/lib/centinela/queue/recheck.req`, el único directorio donde la web puede
escribir, y una unidad `path` de systemd arranca el colector como root.

```
  panel  ──POST api.php──▶  queue/recheck.req
                                  │
                                  │  centinela-recheck.path
                                  ▼
                     centinela-recheck.service  (root)
                     centinela-collect --fresh
                                  │
                                  ▼
                            state.json nuevo
                                  │
  panel  ◀──sondea api.php?v=stamp───┘
```

El fichero de la cola es solo una señal: su contenido no decide nada, el
servicio ejecuta siempre la misma orden. Aunque alguien lograra escribir ahí,
lo único que conseguiría es que el servidor se mida a sí mismo.

`--fresh` ignora la caché de los módulos: sin eso, apartados como el correo o
los certificados devolverían el valor guardado y la recomprobación no
reflejaría el arreglo recién hecho. Se exceptúa lo que viene de fuera (el
catálogo de versiones de Plesk), que no cambia porque aquí se arregle algo y
multiplicaba por tres lo que tarda la recogida.

Cuando llega el estado nuevo, el panel compara: si el identificador del
hallazgo ya no aparece, la incidencia queda marcada como resuelta; si sigue,
muestra el detalle actualizado. La petición está limitada a 6 por minuto y 40
por hora y exige sesión y token CSRF.

### Actuar sobre una IP

El botón **Bloquear** de la tabla de orígenes usa la misma fontanería que la
recomprobación, pero con una diferencia importante: aquí la petición sí lleva
datos (la IP y el jail), así que el ejecutor privilegiado trata todo lo que
llega como sospechoso.

```
  panel ──POST api.php──▶ queue/actions/<id>.json
                                  │  centinela-action.path (DirectoryNotEmpty)
                                  ▼
                        centinela-action  (root)
                        valida ──▶ fail2ban-client set <jail> banip <ip>
                                  │
                            actions.json + actions.log
                                  │
  panel ◀──api.php?v=action&id────┘
```

Lo que valida `centinela-action` antes de ejecutar nada:

- La acción es `ban` o `unban`, y nada más.
- La dirección es una IP válida, no privada ni reservada.
- No cae dentro de las redes del propio servidor (`ip -o addr`), ni de
  `ip_allowlist`, ni de `actions.never_ban`.
- El jail existe en el fail2ban que corre ahora mismo; si el configurado no
  está, falla de forma visible en vez de elegir otro.
- La petición no tiene más de 5 minutos, y se atienden 20 por pasada como
  máximo.

El fichero de petición se borra siempre y lo primero, antes de validar: si algo
falla después, no puede quedarse ahí haciendo que systemd llame en bucle. Cada
acción queda en `actions.log` con quién la pidió, desde dónde y qué respondió
fail2ban. Tras una acción con éxito se encola una recogida para que la tabla
refleje el cambio en segundos.

La capa web, además, se niega a bloquear la IP desde la que estás conectado:
es el error fácil de cometer, y la validación de verdad está en el ejecutor.

### Aplicar una corrección desde la incidencia

Las incidencias que tienen arreglo conocido llevan un botón junto a «Volver a
comprobar». No hay un intérprete genérico detrás: cada corrección está escrita a
mano en `lib/fixes.php` y el panel solo manda su **clave**.

```
  panel ──POST api.php {action:fix, fix:"f2b.reload"}──▶ queue/actions/<id>.json
                                  │
                                  ▼
                        centinela-action  (root)
                        fix_get('f2b.reload')  ──▶ null = no se ejecuta nada
                                  │
                        pasos (argv, sin shell) ──▶ comprobación ──▶ recogida
```

Por qué el catálogo es cerrado y no se ejecuta el `cmd` de la guía, que sería lo
inmediato: esos comandos están escritos para que los lea una persona. Muchos
llevan marcadores como `NOMBRE`, `DOMINIO` o `RANGO` que uno sustituye al
copiarlos; ejecutarlos tal cual haría cosas absurdas. Otros son de diagnóstico,
no de arreglo. Y alguno sería activamente dañino: vaciar la cola de correo no
ayuda si la causa resulta ser una cuenta comprometida enviando spam.

Qué entra en el catálogo: solo lo **idempotente, rápido y sin corte de
servicio**. Aplicarlo dos veces no hace daño, termina en segundos y no deja una
web ni un buzón sin responder.

| Clave | Resuelve | Qué hace |
|---|---|---|
| `f2b.start` | `f2b.down` | Habilita y arranca fail2ban |
| `f2b.reload` | `f2b.nojails` | Valida la configuración y recarga los jails |
| `sophos.start` | `sec.sophos` | Arranca el antivirus y el temporizador de firmas |
| `plesk.autoupdates` | `plesk.updater` | Activa el actualizador del panel |

| `upd.security.apply` | `upd.security` | Aplica las actualizaciones de seguridad *(larga)* |
| `upd.backlog.apply` | `upd.backlog` | Actualiza los paquetes pendientes *(larga)* |

Qué se ha dejado fuera **a propósito**:

- Lo que borra datos (`journalctl --vacuum-time`): libera disco, pero se lleva
  registros que quizá hagan falta para investigar.
- Lo que puede dejarte fuera del servidor (`PasswordAuthentication no`). Ese no
  debería tener botón nunca, ni con confirmación.
- El reinicio, que se lleva por delante el propio panel.

Cada corrección declara además un comando de **comprobación**. Se ejecuta justo
después, y si no cuadra el panel lo dice en vez de cantar victoria. La prueba
definitiva llega enseguida: al terminar se encola una recogida completa y el
panel espera a verla para confirmar que la incidencia ha desaparecido. Por eso
el veredicto distingue tres finales: *resuelta*, *aplicada pero sigue presente*
y *no se ha podido aplicar*.

Añadir una corrección nueva es una entrada en `fix_catalog()`, nada más. El
campo `available` sirve para no ofrecer el botón donde no aplica: el antivirus
de Plesk es `plesk-sophos-av` en unas instalaciones y `sav-protect` en otras.

#### Las correcciones largas

`apt` tarda minutos y no cabe en el `TimeoutStartSec` del ejecutor. Las
entradas marcadas `long` no se ejecutan ahí: el ejecutor abre un trabajo en
`jobs/<id>.json`, lo lanza en una unidad transitoria y contesta en el acto.

```
  centinela-action ──systemd-run --unit=centinela-job──▶ centinela-job (root)
         │                                                     │ escribe
         │ responde «en marcha»                                ▼
         ▼                                          jobs/<id>.json
  panel ──api.php?v=job&id=──────────────────────────────▶ progreso en vivo
```

La unidad transitoria **se llama siempre igual**. No es un descuido: es lo que
impide que se solapen dos trabajos. systemd se niega a arrancar una unidad que
ya existe, así que la exclusión mutua la garantiza él y no un cerrojo nuestro —
dos `apt` a la vez acabarían chocando por el cerrojo de dpkg de todas formas.

La salida se sigue **en vivo**: `run()` acepta un callback que recibe cada trozo
según sale, y el trabajo lo vuelca al fichero cada dos segundos. Sin eso, un apt
de tres minutos sin una sola línea en pantalla parece colgado.

Las dos correcciones largas llevan `warn`, que el panel destaca en la
confirmación: reinician los servicios que se actualicen. Y si al terminar queda
un reinicio pendiente, el trabajo lo dice — es la pregunta inmediata de quien
acaba de pulsar. Reiniciar sigue sin tener botón.

### Cruce con fail2ban

El análisis del log dice quién ataca; fail2ban dice a quién retiene. Ninguna
de las dos mitades responde por sí sola a la pregunta que importa —*¿esto lo
está parando algo?*— así que el colector las junta al final de la recogida
(`cross_reference_bans`), cuando ya tiene ambos módulos.

Cada IP de la tabla queda marcada con los jails que la bloquean, y cuando
aparecen atacantes con volumen y sueltos se genera el hallazgo
`atk.unblocked`: aviso a partir de 300 intentos en 7 días, crítico a partir de
1.000. Es el fallo silencioso típico: fail2ban corriendo, jails activos, y un
atacante que reparte los intentos entre servicios y nunca llega al umbral de
ninguno.

El mapa de bloqueados sale de `fail2ban-client banned` en una sola llamada, sin
el recorte por jail de la lista que se muestra: una lista truncada daría por
libre a quien sí está bloqueado.

### Análisis de los logs web

El log de autenticación cuenta quién intenta entrar por SSH o por correo. El
módulo `web` cuenta lo otro, que en un servidor de hosting suele ser la vía de
entrada real: quién busca ficheros que no deberían estar publicados, quién
prueba contraseñas contra WordPress y qué ha parado ModSecurity.

Lee los logs de Apache de cada dominio (`access_ssl_log`, `access_log` y sus
`.processed`, que es la parte del día que Plesk ya ha rotado) y el `error_log`,
de donde salen las denegaciones de ModSecurity. Se leen los de Apache y no los
de nginx porque son los que ven las peticiones dinámicas, que es donde están
los escaneos.

Cada petición se clasifica por lo que busca:

| Categoría | Qué es |
|---|---|
| `secreto` | `.env`, `.git`, `wp-config`, `.ssh`, `credentials`, `server-status`… |
| `copia` | Volcados y copias olvidadas: `.sql`, `.bak`, `.old`, `.zip` |
| `ejecucion` | Rutas de ejecución remota conocidas: `eval-stdin.php`, `vendor/phpunit`, shells |
| `wordpress` | `wp-login.php`, `xmlrpc.php`, `wp-admin`, enumeración de usuarios |
| `panel` | phpMyAdmin, Adminer, Tomcat manager y demás paneles ajenos |
| `escaneo` | El resto de 401/403/404 que no son ruido de fondo |

Lo que de verdad importa no es el volumen, que es constante en cualquier
servidor con IP pública, sino **si alguno acertó**: una ruta de `secreto`,
`copia` o `ejecucion` que responda 200 se registra como *acierto* y genera el
hallazgo crítico `web.exposed`. Ahí ya no hay que valorar riesgos: el
contenido se lo llevaron, y lo que hubiera dentro es público.

Los otros dos hallazgos son `web.scan` (IPs con más de 60 peticiones
sospechosas en 7 días, con su botón de bloquear) y `web.wpbrute` (más de 100
peticiones contra el login de WordPress).

Rendimiento: mismo lector incremental que el log de autenticación, con tope de
8 MB por fichero y pasada y 300.000 líneas en total. Antes de aplicar ninguna
expresión regular hay un filtro barato por subcadena, porque la inmensa mayoría
de las líneas son tráfico normal que no hace falta ni interpretar. En este
servidor, con 45 MB de logs, la pasada completa tarda unos 700 ms.

### Modo incidente: el vigilante

El colector completo mide todo el servidor y por eso pasa cada 5 minutos.
`centinela-watch` hace lo contrario: cada minuto, y solo lo que puede
convertirse en un incidente ahora mismo —log de autenticación, logs web y
bloqueos de fail2ban—, que son justo los módulos incrementales. La pasada
cuesta unos **220 ms**.

No toca `state.json` ni el panel, que siguen viviendo del colector. Su único
cometido es que el correo llegue antes: hasta un minuto en lugar de hasta
cinco, y solo para incidencias **críticas**.

```
  centinela-watch.timer  ── 1 min ──▶  attacks + web + banned_map
                                              │
                                     ¿hay algo crítico nuevo?
                                              │ sí
                                     correo «[urgente] …»
```

Los dos comparten `alert_state.json`: el vigilante apunta lo que ha contado en
la clave `watch` y el colector la consulta antes de avisar, de modo que una
misma incidencia no se notifica dos veces. Lo crítico se reavisa cada hora
(`alert_throttle_crit`) en lugar de cada día, porque es lo que justifica ir a
mirar.

Ambos toman el mismo cerrojo (`collect.lock`) antes de leer los almacenes
incrementales: sin él, dos lecturas solapadas se pisarían el desplazamiento del
log y se perderían intentos. Si el colector está trabajando, el vigilante se
salta el pase — la recogida completa llega igual de fresca.

En el panel, las incidencias críticas levantan una franja roja en la cabecera
con enlace directo a qué hacer.

### Geo-valla de los servicios de administración

La política dice desde dónde es legítimo administrar el servidor. Vive en
`/etc/centinela/ssh_guard.json` (solo root la escribe: si la web pudiera
tocarla, un panel comprometido se autoexcluiría de la valla) y se gestiona con
`centinela-admin guard`:

```bash
centinela-admin guard --allow-country ES
centinela-admin guard --allow-ip 203.0.113.0/24
centinela-admin guard --simulate     # qué habría pasado, contra el histórico
centinela-admin guard --observe      # cuenta sin banear
centinela-admin guard --enforce      # activa el baneo
```

Es deliberadamente **reactiva**, no un filtro previo en el firewall: el
administrador entra desde redes dinámicas (casa, Starlink, Tailscale) y una
allowlist estática acabaría dejándole fuera. Con la valla:

- Un **intento fallido** contra SSH o el panel desde fuera de la política se
  banea en fail2ban en cuanto lo ve el vigilante (≤1 min), sin esperar a los
  cinco intentos del jail. Queda registrado en `actions.log` con autor
  `geo-valla`.
- Un **acceso correcto** desde fuera de la política **nunca se banea**: genera
  la alerta crítica `guard.login` con el comando exacto para añadir el origen
  si eres tú, o rotar credenciales si no. Así un viaje no te deja sin servidor.
- Una IP **sin país resuelto** todavía no se toca: la valla espera al geo, no
  adivina. Las IPs que tocan servicios vigilados tienen prioridad en la
  resolución.
- Las direcciones privadas y CGNAT (Tailscale) quedan fuera del alcance: no
  llegan de internet.

`--enforce` se niega a activarse si la política dejaría fuera algún acceso
correcto del histórico (se fuerza con `--force`), o si está vacía.

### Exportación a syslog remoto

Para integrar el servidor en un SIEM sin dar acceso al panel:

```bash
centinela-admin syslog --server siem.miempresa.com:514 udp
centinela-admin syslog --test
```

Al final de cada recogida el colector emite por UDP o TCP, en RFC 5424 con el
cuerpo en clave=valor:

| Evento | Contenido |
|---|---|
| `event=health` | Nota, grado y recuento por severidad — serie temporal para el SIEM |
| `event=attacks` | Intentos de hoy y 7 días, IPs únicas, atacantes sueltos, actividad web, baneos de la geo-valla |
| `event=finding state=new\|changed\|resolved` | Solo transiciones, no estados: el lado remoto alerta sobre «apareció X», no sobre «X sigue ahí» |

La severidad syslog refleja la de la incidencia (crit→2, warn→4, info→6) y el
umbral se filtra con `--min-sev`. Un fallo de red del envío nunca afecta a la
recogida.

### Reglas de detección

Sobre lo que ya se recoge, sin coste adicional:

| Hallazgo | Cuándo salta |
|---|---|
| `atk.spike` | Los intentos de hoy triplican la media diaria |
| `atk.success_suspect` | Acceso correcto por contraseña desde una IP que ya había fallado más de 20 veces |
| `atk.unblocked` | Atacantes con 300+ intentos en 7 días que ningún jail retiene (1.000+ pasa a crítico) |
| `atk.newlogin` | Acceso correcto desde una dirección nunca vista, con su país y operador |
| `atk.userenum` | Una IP prueba 15 o más nombres de usuario distintos: enumeración |
| `atk.prefix` | Un mismo prefijo concentra 400+ intentos o el 25% del total desde 3 o más IPs |
| `atk.distributed` | Las IPs distintas de hoy triplican la media y pasan de 30: campaña repartida para esquivar los umbrales |
| `web.exposed` | Una ruta sensible respondió 200 |
| `web.scan` | IPs con más de 60 peticiones sospechosas en 7 días |
| `web.wpbrute` | Más de 100 peticiones contra el login de WordPress |
| `guard.login` | Acceso correcto a un servicio vigilado desde fuera de la política de la geo-valla |

`atk.newlogin` necesita un día de historia antes de decir nada: recién
instalado, todas las direcciones serían «nunca vistas».

### Lectura incremental de los logs

El analizador guarda inodo y desplazamiento entre ejecuciones, de modo que
cada pasada solo procesa lo nuevo. Detecta la rotación y reanuda desde el
principio. Con la caché caliente, una recogida completa tarda unos 5 segundos.

### Enriquecimiento de red

Los datos de ASN, prefijo, país y operador salen del servicio DNS de Team
Cymru: sin claves de API y sin enviar nada a terceros más allá de la consulta
DNS. Se cachean 30 días y se resuelven como máximo 12 IPs nuevas por pasada.

---

## Seguridad

**Acceso al panel.** Usuario y contraseña con bcrypt (coste 12) más TOTP
obligatorio (RFC 6238, verificado contra los vectores del estándar). Bloqueo
tras 5 intentos fallidos, sesiones de 2 h atadas al agente, CSRF en el
formulario y registro de todos los accesos.

**Cabeceras.** CSP estricta sin `unsafe-eval` ni recursos externos,
`frame-ancestors 'none'`, HSTS, `nosniff` y `Referrer-Policy: no-referrer`.
No hay ninguna dependencia de CDN: las gráficas son SVG generado en servidor.

**Looking glass.** Es la única superficie que recibe entrada del usuario:

- lista cerrada de comandos; el usuario elige una clave, nunca un binario;
- nunca se invoca un shell: `proc_open` recibe un array de argumentos;
- el destino se valida por sintaxis y **se resuelve** antes de usarlo;
- se rechazan las direcciones privadas y reservadas, incluso si el destino es
  un dominio que resuelve a una IP interna;
- tiempo de espera, salida truncada, límite por minuto y por hora, y captcha
  autocontenido en la primera consulta.

**Filtrado por IP.** `ip_allowlist` viene vacía: el filtrado se espera en el
cortafuegos de red. Para añadir una capa en la aplicación, basta rellenarla
con IPs o rangos CIDR.

---

## Uso diario

```bash
centinela-admin check          # diagnóstico de la instalación
centinela-admin show           # configuración vigente
centinela-admin passwd         # cambiar contraseña
centinela-admin passwd --stdin # sin terminal, para automatizar
centinela-admin totp --new     # regenerar el segundo factor
centinela-admin email a@b.com  # cambiar el destinatario de los avisos
centinela-admin test-mail      # probar la entrega

centinela-report --weekly      # enviar el informe ahora
centinela-report --alerts      # comprobar y avisar si hay novedades
centinela-report --weekly --dry-run   # ver el correo sin enviarlo

centinela-collect --fresh      # recoger ahora ignorando las cachés

centinela-watch --dry-run      # ver qué avisaría el vigilante, sin enviarlo

journalctl -u centinela-collect -f    # seguir el colector
journalctl -u centinela-watch -f      # seguir el vigilante de incidentes
journalctl -u centinela-recheck -f    # seguir las recomprobaciones del panel
journalctl -u centinela-action -f     # seguir los bloqueos pedidos desde el panel
tail -f /var/lib/centinela/actions.log   # auditoría de acciones sobre IPs
systemctl list-timers 'centinela*'    # ver la próxima ejecución
systemctl status centinela-recheck.path   # ¿está vigilando la cola?
```

---

## Configuración

`/etc/centinela/config.php` devuelve un array. Lo más habitual de tocar:

```php
'mail' => [
    'to'             => ['admin@midominio.com'],  // varios separados por coma
    'alert_min_sev'  => 'warn',   // 'warn' o 'crit'
    'alert_throttle' => 86400,    // no repetir el mismo aviso en 24 h
],

'platform'        => 'generic',            // plesk | hestia | generic; vacío = detectar

'ip_allowlist'    => ['203.0.113.0/24'],   // vacía = sin filtro
'trusted_proxies' => ['173.245.48.0/20'],  // rangos de Cloudflare, si aplica

'actions' => ['jail' => 'centinela'],      // jail de fail2ban para los bloqueos del panel

// Sin panel, si los logs o certificados no están en los sitios habituales:
'web'   => ['logs'  => ['/srv/www/*/logs/access.log']],
'certs' => ['paths' => ['/etc/ssl/misitio/*.crt']],

'lg' => [
    'public'     => true,   // false = exige sesión
    'per_minute' => 10,
    'per_hour'   => 60,
],
```

Tras editarla, PHP puede tardar hasta un minuto en releerla por opcache;
`systemctl reload plesk-php84-fpm` la aplica al momento.

### Detrás de Cloudflare

Si el subdominio pasa por el proxy de Cloudflare, añade sus rangos a
`trusted_proxies` para que el registro de accesos y el límite de frecuencia
vean la IP real del visitante y no la del proxy.

---

## Cómo se calcula la nota

Se parte de 100 y se resta el peso de cada incidencia: 18 puntos por crítica y
6 por aviso. Dentro de una misma categoría los hallazgos siguientes pesan la
mitad del anterior, para que diez avisos del mismo tipo no hundan la nota igual
que diez problemas distintos.

| Nota | Lectura |
|---|---|
| 90–100 | Excelente |
| 75–89 | Bueno |
| 50–74 | Mejorable o atención |
| 0–49 | Crítico |

---

## Añadir comprobaciones

Cada módulo es una función que devuelve un array con una clave `findings`:

```php
function collect_mi_modulo(): array
{
    $findings = [];
    if ($algo_va_mal) {
        $findings[] = finding(
            'mimod.problema',      // el prefijo agrupa a efectos de la nota
            SEV_WARN,              // SEV_CRIT | SEV_WARN | SEV_INFO
            'Título breve',
            'Explicación de una línea',
            'comando --que-lo-arregla',
            guide(
                'Por qué importa, en una o dos frases.',
                [
                    ['do' => 'Primer paso', 'cmd' => 'comando del primer paso'],
                    ['do' => 'Un paso puede no llevar comando: hazlo en la interfaz de Plesk.'],
                ],
                'comando --que-verifica',       // opcional: cómo saber que quedó resuelto
                'Aviso si el cambio puede cortar el acceso',   // opcional
                'https://enlace/a/la/documentacion'           // opcional
            )
        );
    }
    return ['datos' => $loQueSea, 'findings' => $findings];
}
```

Se registra en `bin/centinela-collect`:

```php
module('mi_modulo', 'collect_mi_modulo', $report, $all, $quiet, 600);
```

El identificador tiene que ser estable entre recogidas: es lo que compara el
botón de recomprobar para decidir si la incidencia ha desaparecido.

El último parámetro de `module()` es el tiempo de caché en segundos; ponlo si
el módulo es lento. Un módulo que falle queda aislado: se convierte en un aviso y el resto
de la recogida continúa.

---

## Desinstalación

```bash
./install.sh --uninstall
```

Retira temporizadores, código y comandos. Conserva a propósito
`/etc/centinela`, `/var/lib/centinela` y el subdominio en Plesk.

---

## Publicación y actualización automática

Centinela se publica en GitHub bajo **AGPL-3.0** y las instalaciones pueden
mantenerse al día solas desde las *releases* del repositorio.

### Poner en marcha las actualizaciones

```bash
centinela-admin update --repo usuario/centinela   # tu repositorio
centinela-admin update --mode auto                # auto | patch | notify
centinela-update --check                          # ¿hay versión nueva?
centinela-admin update --now                      # aplicar ya
```

Modos: `auto` aplica cualquier versión nueva; `patch` solo las de parche
(1.0.x, no cambios mayores); `notify` solo avisa en el panel y por registro.

Un timer diario (`centinela-update.timer`, 04:30 con dispersión) consulta la
última *release*, y según el modo la aplica. Cada actualización automática:

1. Deja constancia del aviso, que el panel muestra en la cabecera.
2. Descarga el paquete de la *release* y, si hay `SHA256SUMS`, **verifica el
   checksum** antes de tocar nada.
3. Hace copia del código privilegiado y del docroot.
4. Aplica con `install.sh --upgrade`.
5. Comprueba la salud: sintaxis PHP y que el colector completa una recogida.
6. Si algo falla, **revierte** a la versión anterior y recarga PHP.

Todo queda en `/var/lib/centinela/update.log`.

### Publicar una versión

El repositorio incluye un *workflow* (`.github/workflows/release.yml`) que, al
empujar una etiqueta `vX.Y.Z`, valida la sintaxis PHP, empaqueta el árbol,
genera `SHA256SUMS` y crea la *release*. Los servidores la recogen solos.

```bash
# subir la versión en lib/util.php e install.sh, luego:
git tag v1.0.1
git push origin v1.0.1
```

### Qué NO se publica

`.gitignore` excluye toda credencial y estado: la configuración real vive en
`/etc/centinela/` (hashes bcrypt y secretos TOTP), nunca en el árbol. El
repositorio solo contiene código.
