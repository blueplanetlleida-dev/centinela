# Centinela para una flota de servidores

Un **agente** en cada servidor Linux recoge su salud y la envía cada minuto a
un **central**, que guarda el histórico, evalúa las reglas, avisa por correo y
muestra todos los servidores en un solo panel.

```
 servidor A ─┐  centinela-agent (Python, servicio systemd)
 servidor B ─┼─► HTTPS saliente, cada 60 s ─► centinela-central
 servidor C ─┘  sin ningún puerto abierto      API + SQLite + panel + alertas
```

A diferencia del Centinela original (PHP), el agente no depende del servidor
web de la máquina: es Python de la librería estándar y funciona en cualquier
Linux con systemd y Python 3.8 o superior.

## Qué recoge el agente

| Cada | Qué |
|---|---|
| 60 s | CPU (uso, espera de E/S, *steal*), carga, memoria y swap, procesos, sistemas de ficheros (ocupación e inodos), E/S por disco, tráfico por interfaz, temperaturas y ventiladores (hwmon) |
| 60 s | Unidades de systemd caídas |
| 5 min | RAID por software (mdadm), pools ZFS, sensores IPMI si hay BMC |
| 15 min | Sincronización de la hora |
| 30 min | SMART de cada disco (SATA, SAS, NVMe), sin despertar los que estén en reposo |
| 6 h | Inventario: sistema, núcleo, virtualización, procesador, memoria, IPs, panel, actualizaciones pendientes (las de seguridad aparte) y reinicio pendiente |

Lo que no existe en una máquina no se intenta: en una VM no hay sensores ni
SMART y el panel lo dice así, nunca como cero.

Si el central no responde, los informes se guardan en
`/var/lib/centinela-agent/spool` (hasta dos días) y se envían en cuanto vuelve.

## Reglas del central

| Problema | Aviso | Crítico |
|---|---|---|
| Sin contacto | — | 5 min sin informe (o 3 intervalos) |
| Disco o inodos | 90 % | 95 % |
| Raíz en solo lectura | — | siempre |
| Memoria | 90 % | 95 % |
| Swap | 80 % | — |
| Carga de 15 min por núcleo | 2 | 4 |
| CPU retenida por el anfitrión (*steal*) | 25 % | — |
| Temperatura | umbral del sensor o 85 °C (CPU) / 60 °C (disco) | umbral crítico del sensor o 95 / 70 °C |
| RAID degradado, SMART en fallo, aviso crítico NVMe | — | siempre |
| Sectores reasignados o pendientes, errores de medio NVMe | siempre | — |
| Desgaste de SSD | 90 % | 100 % |
| Servicios de systemd caídos, hora sin sincronizar, reloj desviado más de 2 min | siempre | — |
| Actualizaciones de seguridad pendientes | siempre | — |

Una alerta se abre una vez, se actualiza mientras dura y se cierra sola. El
correo espera a que un problema dure 5 minutos (`notify_after`), salvo el de
«sin contacto», y agrupa en un solo mensaje todo lo pendiente.

## Instalar el central

En un servidor aparte (si cae un servidor vigilado, el central sigue y avisa):

```sh
git clone https://github.com/blueplanetlleida-dev/centinela.git
cd centinela
sudo sh central/install.sh --url https://flota.ejemplo.com
```

Crea el usuario de sistema `centinela-central`, el código en
`/opt/centinela-central` (con su entorno de Python), la configuración en
`/etc/centinela-central/central.conf`, los datos en
`/var/lib/centinela-central` y el servicio `centinela-central`, que escucha
en `127.0.0.1:8470`. La primera vez imprime la contraseña del usuario `admin`.

Falta publicarlo con HTTPS: el instalador imprime el bloque para nginx y para
Caddy. Con Caddy basta con:

```
flota.ejemplo.com {
    reverse_proxy 127.0.0.1:8470
}
```

Si se sirve bajo una ruta (`https://dominio.com/flota`), instala con
`--url https://dominio.com/flota --base-path /flota` y en nginx usa
`location ^~ /flota/ { proxy_pass http://127.0.0.1:8470; ... }`, sin barra
final en `proxy_pass` para que la ruta llegue entera.

Para el correo de avisos, rellena `[smtp]` en `central.conf` y reinicia el
servicio.

### Administración

```sh
centinela-central user passwd admin      # cambiar contraseña
centinela-central user totp admin        # activar doble factor
centinela-central user add NOMBRE        # otro usuario
centinela-central enroll-code --label web-01   # código de alta desde la terminal
centinela-central hosts                  # lista rápida
```

### Desinstalar el central

El instalador se queda en `/opt/centinela-central/install.sh`, así que no hace
falta el repositorio:

```sh
sudo sh /opt/centinela-central/install.sh --uninstall           # quita servicio y código
sudo sh /opt/centinela-central/install.sh --uninstall --purge   # y además configuración, datos y usuario
```

Sin `--purge` se conservan `/etc/centinela-central`, `/var/lib/centinela-central`
y el usuario `centinela-central`: reinstalar sigue donde se dejó, con los mismos
servidores, historial y usuarios. `--purge` borra la base de datos con toda la
flota, así que pide escribir `BORRAR` para confirmar (o `--yes` si no hay
terminal) y antes recuerda cómo sacar una copia. Los agentes que informaban a
ese central siguen intentándolo y encolan hasta dos días: hay que darlos de
alta en otro central o desinstalarlos.

## Añadir un servidor

En el panel, **Añadir servidor** genera un código de un solo uso (caduca en 24
horas por defecto) y la orden que hay que ejecutar en la máquina:

```sh
curl -fsSL https://flota.ejemplo.com/dl/install.sh -o centinela-install.sh
sudo sh centinela-install.sh --code ABCD-EFGH-JKLM
```

El instalador descarga el agente del propio central, comprueba su SHA-256, lo
deja en `/opt/centinela-agent`, se da de alta con el código y arranca el
servicio `centinela-agent`. Reinstalar una máquina con otro código conserva su
historial: el central la reconoce por `/etc/machine-id` y renueva el token.

```sh
centinela-agent status         # a qué central informa y cuándo fue el último envío
centinela-agent once           # informe completo por pantalla, sin enviar nada
journalctl -u centinela-agent -f
sudo sh /opt/centinela-agent/install.sh --uninstall --purge
```

Para que un servidor físico informe de todo conviene tener instalados
`smartmontools` (salud de discos), `lm-sensors` (para cargar los módulos de los
sensores) e `ipmitool` si tiene BMC.

## Seguridad

- **El agente no escucha en ningún puerto.** Solo hace conexiones salientes al
  central, así que funciona tras NAT y con el cortafuegos en DROP.
- **Solo HTTPS**, salvo hacia `127.0.0.1`: el token viaja en cada envío.
- **Un token por servidor**, guardado como hash SHA-256 en el central. Borrar el
  servidor en el panel lo revoca sin tocar los demás.
- **Códigos de alta** de un solo uso, con caducidad y límite de intentos por IP.
- **El central no puede ejecutar nada en los servidores.** Las correcciones
  remotas, si llegan, serán un catálogo cerrado y opcional por servidor.
- Panel con contraseñas scrypt, doble factor TOTP opcional, sesiones en
  cookie `HttpOnly`/`SameSite`, CSRF en todos los formularios, límite de
  intentos de acceso y CSP sin scripts en línea.
- El agente corre como root (SMART, IPMI y parte de `/proc` lo exigen) pero con
  `ProtectSystem=full`, `NoNewPrivileges` y `MemoryMax=256M`, con prioridad
  baja de CPU y de E/S.

## Datos y retención

SQLite en `/var/lib/centinela-central/central.db` (modo WAL). Cada informe se
guarda tal cual 48 horas; después quedan medias de 5 minutos durante 35 días
y de 1 hora durante 400 días (disco y temperatura guardan el máximo del tramo,
no la media). Para decenas de servidores ocupa unas decenas de MB.

Copia de seguridad en caliente:

```sh
sqlite3 /var/lib/centinela-central/central.db ".backup /ruta/central-$(date +%F).db"
```
