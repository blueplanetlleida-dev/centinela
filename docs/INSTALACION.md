# Centinela: instalación desde cero en un servidor

Guía paso a paso para dejar Centinela funcionando en un servidor nuevo, sea
Plesk, HestiaCP o Linux sin panel. Tiempo estimado: 10 minutos.

Repositorio: https://github.com/blueplanetlleida-dev/centinela

## 1. Antes de empezar

Necesitas:

- Acceso **root** por SSH al servidor.
- Un **subdominio** para el panel (por ejemplo `seguridad.midominio.com`) con
  su registro **A apuntando a la IP del servidor**. Sin eso el certificado no
  se puede emitir; el instalador avisa y sigue sin SSL.
- Una **dirección de correo** de administrador: recibe las alertas y el
  informe semanal.
- Una aplicación de **autenticación TOTP** en el móvil (Google Authenticator,
  Aegis, 1Password, Authy…). El segundo factor es obligatorio.

Requisitos por plataforma:

| Plataforma | Qué debe haber ya |
|---|---|
| **Plesk Obsidian** | Nada más. Usa el PHP de Plesk y la extensión Let's Encrypt. El dominio padre del subdominio debe existir en Plesk. |
| **HestiaCP** | Nada más. El panel se crea como dominio web del usuario `admin` (o el que indiques con `--hestia-user`). |
| **Sin panel** (Ubuntu/Debian/AlmaLinux) | `git`, `php-cli`, `php-fpm`, y **nginx o Apache**. Recomendado: `fail2ban` y `certbot`. |

Sin panel, en Ubuntu/Debian, esto instala todo lo necesario:

```bash
apt-get update
apt-get install -y git nginx php-cli php-fpm php-json fail2ban certbot python3-certbot-nginx dnsutils
```

En AlmaLinux/RHEL:

```bash
dnf install -y git nginx php-cli php-fpm fail2ban certbot python3-certbot-nginx bind-utils
systemctl enable --now nginx php-fpm fail2ban
```

## 2. Descargar e instalar

Como root:

```bash
cd /root
git clone https://github.com/blueplanetlleida-dev/centinela.git
cd centinela
./install.sh --domain seguridad.midominio.com --email admin@midominio.com
```

El instalador:

1. Detecta la plataforma (Plesk, Hestia o sin panel) y el PHP a usar.
2. Crea el sitio del panel: subdominio en Plesk, dominio en Hestia, o un vhost
   propio de nginx/Apache con su pool PHP-FPM en `/var/www/centinela`.
3. Copia el código privilegiado a `/usr/local/centinela` (solo root) y la
   interfaz web al docroot del sitio.
4. Amplía `open_basedir` para que la web pueda leer la configuración y el
   estado.
5. Genera `/etc/centinela/config.php` con el secreto TOTP.
6. Fuera de Plesk, crea el jail `centinela` en fail2ban para los bloqueos
   hechos desde el panel.
7. Instala los temporizadores de systemd: colector cada 5 minutos, vigilante
   cada minuto, informe semanal, actualizador diario.
8. Hace la primera recogida y emite el certificado Let's Encrypt.
9. Te pide la **contraseña** del usuario `admin` y muestra el **código QR** del
   segundo factor. Escanéalo en ese momento.

Opciones útiles:

| Opción | Para qué |
|---|---|
| `--platform plesk\|hestia\|generic` | Forzar la plataforma si la detección no acierta |
| `--hestia-user USUARIO` | En Hestia, usuario que alojará el panel (por defecto `admin`) |
| `--webserver nginx\|apache` | Sin panel, cuál usar si conviven los dos |
| `--update-repo blueplanetlleida-dev/centinela --update-mode auto` | Dejar el auto-update configurado desde el principio |
| `--private-lg` | Que el looking glass exija sesión en vez de ser público |
| `--interval 10min` | Cambiar la frecuencia del colector |
| `--weekly-day Fri --weekly-hour 09` | Cambiar el día y la hora del informe semanal |
| `--skip-ssl` | No emitir certificado |
| `-y` | No pedir confirmación |

Si algo falla a medias, se puede repetir la misma orden: el instalador
conserva la configuración existente y no duplica nada.

## 3. Comprobar que funciona

```bash
centinela-admin check        # diagnóstico: todo debe salir [ok]
centinela-admin test-mail    # tiene que llegar un correo de prueba
```

Entra en `https://seguridad.midominio.com/` con el usuario `admin`, tu
contraseña y el código de la aplicación TOTP. El looking glass público está en
`/lg.php`.

Si el correo de prueba no llega, lo más habitual es que la IP del servidor no
tenga **PTR** (DNS inverso) o que falte **SPF**. El propio panel lo dice en el
apartado de correo, con la guía para arreglarlo.

## 4. Activar la actualización automática

Cada servidor puede actualizarse solo desde las releases de GitHub. Comprueba
antes de aplicar, hace copia y revierte si el panel deja de funcionar.

```bash
centinela-admin update --repo blueplanetlleida-dev/centinela --mode auto
centinela-update --check     # debe decir la versión instalada y la última
```

Modos: `auto` aplica cualquier versión nueva, `patch` solo las de parche
(1.1.x), `notify` solo avisa en el panel. El actualizador corre una vez al
día; para forzarlo ahora: `centinela-admin update --now`.

## 5. Ajustes opcionales recomendados

**Geo-valla** (desde dónde es legítimo administrar el servidor). Permite tu
país y tus rangos fijos, simula contra el histórico y actívala:

```bash
centinela-admin guard --allow-country ES
centinela-admin guard --allow-ip 203.0.113.0/24     # tu oficina, VPN, etc.
centinela-admin guard --simulate
centinela-admin guard --enforce
```

Un intento fallido contra SSH o el panel desde fuera de la política se banea
al primer intento. Un acceso correcto desde fuera nunca se banea, solo avisa.

**Usuarios adicionales del panel:**

```bash
centinela-admin user --add nombre correo@dominio.com
```

**Exportar a un SIEM** por syslog remoto:

```bash
centinela-admin syslog --server siem.miempresa.com:514 udp
centinela-admin syslog --test
```

**Detrás de Cloudflare:** añade sus rangos a `trusted_proxies` en
`/etc/centinela/config.php`, o el límite de frecuencia y la geo-valla verán la
IP de Cloudflare como cliente.

## 6. Mantenimiento

```bash
centinela-admin show                  # configuración vigente
centinela-admin passwd                # cambiar contraseña
centinela-admin totp --new            # regenerar el segundo factor
journalctl -u centinela-collect -f    # seguir el colector
journalctl -u centinela-watch -f      # seguir el vigilante
tail -f /var/lib/centinela/actions.log   # bloqueos hechos desde el panel
```

Actualizar a mano, si no usas el auto-update:

```bash
cd /root/centinela && git pull && ./install.sh --upgrade -y
```

Desinstalar (conserva configuración y datos):

```bash
./install.sh --uninstall
```

## 7. Rutas que conviene conocer

| Ruta | Contenido |
|---|---|
| `/usr/local/centinela/` | Código privilegiado (root) |
| `/etc/centinela/config.php` | Configuración y credenciales (root:centinela 0640) |
| `/etc/centinela/ssh_guard.json` | Política de la geo-valla (solo root la escribe) |
| `/var/lib/centinela/` | Estado, histórico, sesiones, cola de acciones |
| Docroot del subdominio | Interfaz web (usuario del sitio) |

## Notas por plataforma

**Plesk.** El usuario del subdominio es el de toda la suscripción: cualquier
sitio alojado bajo el mismo dominio padre puede leer la configuración del
panel. Lo más seguro es dar al panel una suscripción propia.

**HestiaCP.** El instalador crea una plantilla PHP-FPM derivada
(`centinela-PHP-x_y`) con el `open_basedir` ampliado y se la asigna al dominio.
Si en Hestia cambias la plantilla del dominio, vuelve a asignarla.

**Sin panel.** El panel corre con el usuario de sistema `centinela-web` y un
pool PHP-FPM propio. Si tus logs web o certificados no están en
`/var/log/nginx`, `/var/log/apache2` o `/etc/letsencrypt/live`, indica los
patrones en `config.php` (`web.logs` y `certs.paths`).
