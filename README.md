# cPanel WHM IOC Auto Blocker

Script de respuesta automática para servidores **cPanel/WHM** que detecta intentos de explotación pre-auth contra **WHM (`cpsrvd` / `whostmgrd`)** en los archivos de sesión raw y bloquea la IP atacante con **CSF**.

Está pensado como **capa complementaria** al parcheo oficial de cPanel para [CVE-2026-41940](https://nvd.nist.gov/vuln/detail/CVE-2026-41940) (authentication bypass en el flujo de login). **No reemplaza** la actualización de cPanel.

---

## Contexto: CVE-2026-41940

- **Tipo:** Authentication bypass en el login flow de cPanel & WHM (CWE-306, *Missing Authentication for Critical Function*).
- **Severidad:** CVSS 3.1 = **9.8 CRITICAL** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
- **Impacto:** Atacante remoto no autenticado puede obtener acceso al panel manipulando el archivo de sesión durante el login (claves como `tfa_verified=1`, `user=root`) que se promueven al cache JSON cuando se disparan rutas de código tipo `do_token_denied`.
- **Estado:** Explotación in-the-wild reportada.

### Mitigación principal: actualizar cPanel/WHM

Versiones parcheadas (mínimas) por rama:

| Rama | Versión parcheada |
|------|-------------------|
| 11.110 (LTS antiguas) | `11.110.0.97` |
| 11.118 | `11.118.0.63` |
| 11.126 | `11.126.0.54` |
| 11.132 | `11.132.0.29` |
| 11.134 | `11.134.0.20` |
| 11.136 (CURRENT) | `11.136.0.5` |
| WP Squared | `11.136.1.7` |

Actualizar el servidor:

```bash
/scripts/upcp --force
```

Verificar la versión instalada:

```bash
/usr/local/cpanel/cpanel -V
```

### Referencias oficiales

- Advisory cPanel: <https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-41940>
- Notas de versión cPanel: <https://docs.cpanel.net/release-notes/release-notes>
- Changelog WP Squared: <https://docs.wpsquared.com/changelogs/versions/changelog/#13617>

---

## Qué hace el script

Analiza los archivos de sesión raw de cPanel en:

```
/var/cpanel/sessions/raw/
```

Cuando un archivo cumple **todas** las condiciones del IOC, extrae la IP y la bloquea en CSF con un comentario fijo:

- `token_denied=` presente.
- `cp_security_token=/cpsess`.
- `origin_as_string=` con `app=whostmgrd`.
- `origin_as_string=` con `method=badpass`.

El IOC apunta al patrón observado en sondas/explotación contra WHM relacionadas con CVE-2026-41940 y bypass por manipulación de sesión. El script:

1. Identifica la IP atacante en `address=` del `origin_as_string`.
2. La bloquea con `csf -d` (si no está ya en `csf.deny`).
3. Registra el evento en `/var/log/auto_block_cpanel_ioc.log`.

> **Nota:** Este patrón no corresponde a actividad legítima como expiración de sesión, errores de login normales o uso de webmail, lo que reduce el riesgo de falsos positivos, pero **no lo elimina**.

---

## Requisitos

- Servidor con **cPanel/WHM**.
- **CSF (ConfigServer Firewall)** instalado y operativo.
- **Bash** (no es POSIX `sh`; en Debian/Ubuntu `/bin/sh` es `dash` y fallará).
- Acceso **root** (lectura de `/var/cpanel/sessions/raw`, escritura del log y ejecución de CSF).

---

## Instalación

Descargar el script al servidor, por ejemplo a `/root/`:

```bash
curl -fsSL -o /root/auto_block_cpanel_ioc.sh \
  https://raw.githubusercontent.com/devmanifesto/auto_block_cpanel_ioc/main/auto_block_cpanel_ioc.sh
chmod 700 /root/auto_block_cpanel_ioc.sh
```

> Ajustá la URL al repositorio/branch real si lo forkeás.

---

## Uso

### Ejecución manual

```bash
bash /root/auto_block_cpanel_ioc.sh
```

### Modo dry-run (no bloquea, solo loguea)

Útil para validar el patrón IOC antes de habilitar el bloqueo automático:

```bash
bash /root/auto_block_cpanel_ioc.sh --dry-run
```

### Modo debug (verbose en stderr)

```bash
bash /root/auto_block_cpanel_ioc.sh --debug
```

### Ejecución programada (cron)

El script ya implementa **`flock` interno** (lock en `/var/run/auto_block_cpanel_ioc.lock`), por lo que dos ejecuciones simultáneas no se pisan. Cron sugerido cada minuto:

```cron
* * * * * /root/auto_block_cpanel_ioc.sh >/dev/null 2>&1
```

### Variables de entorno opcionales

| Variable | Default | Descripción |
|----------|---------|-------------|
| `AUTO_BLOCK_DRY_RUN` | `0` | Si es `1`, no ejecuta `csf -d`, solo loguea. |
| `AUTO_BLOCK_DEBUG` | `0` | Si es `1`, imprime también en stderr. |
| `AUTO_BLOCK_SESSIONS_DIR` | `/var/cpanel/sessions` | Override del directorio base de sesiones. |
| `AUTO_BLOCK_RAW_DIR` | `$SESSIONS_DIR/raw` | Override del directorio de sesiones raw. |
| `AUTO_BLOCK_LOG_FILE` | `/var/log/auto_block_cpanel_ioc.log` | Override del log. |
| `AUTO_BLOCK_CSF_BIN` | `/usr/sbin/csf` | Ruta al binario CSF. |
| `AUTO_BLOCK_CSF_DENY` | `/etc/csf/csf.deny` | Ruta a `csf.deny`. |
| `AUTO_BLOCK_LOCK_FILE` | `/var/run/auto_block_cpanel_ioc.lock` | Ruta del lockfile. |
| `AUTO_BLOCK_COMMENT` | `Auto blocked: cPanel WHM badpass cpsess IOC (CVE-2026-41940 pattern)` | Comentario en `csf.deny`. |

---

## Logs y operación

Los eventos se registran en:

```
/var/log/auto_block_cpanel_ioc.log
```

Ver últimos eventos:

```bash
tail -100 /var/log/auto_block_cpanel_ioc.log
```

Ver IPs bloqueadas por este script:

```bash
grep "cPanel WHM badpass cpsess IOC" /etc/csf/csf.deny
```

Desbloquear una IP (ejemplo):

```bash
csf -dr 198.51.100.10
```

Sugerencia de rotación con `logrotate` (`/etc/logrotate.d/auto_block_cpanel_ioc`):

```
/var/log/auto_block_cpanel_ioc.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
```

---

## Recomendaciones de hardening adicionales

- Aplicar el parche oficial **antes** de confiar en este script.
- Restringir el acceso a WHM (puertos 2086/2087) por IP de administración.
- Activar y ajustar **cPHulk**.
- Monitorear `/usr/local/cpanel/logs/login_log` y los logs de `cpsrvd`.
- Auditar archivos de sesión sospechosos en `/var/cpanel/sessions/raw/` antes de eliminarlos.
- Mantener backups de `/etc/csf/csf.deny` y `/etc/csf/csf.allow`.

---

## Características de hardening del script

- `set -Eeuo pipefail` y `trap` sobre `ERR` para fallar de forma controlada.
- Verificación de Bash (no funciona en `dash`/`sh` POSIX) y de privilegios root.
- `flock` interno sobre lockfile para evitar ejecuciones concurrentes (cron-safe).
- Validación estricta de IPv4 (octetos `0-255`, sin ceros a la izquierda, descarta `0.0.0.0`, `127.0.0.1`, broadcast).
- `grep -F`/regex con la IP escapada al consultar `csf.deny`, evita falsos matches por el comodín `.`.
- IOC verifica que `app=whostmgrd` y `method=badpass` aparezcan en la **misma línea** `origin_as_string=`.
- Captura del exit code y stderr de `csf -d`; si CSF falla se loguea `BLOCK FAILED` con el motivo.
- Modo `--dry-run` para validar IOC sin bloquear.
- Logging estructurado con timestamp, nivel y PID; permisos `600` sobre el log.
- Métricas finales por ejecución: `scanned`, `matched`, `blocked`, `skipped_invalid`.

## Limitaciones conocidas

- Solo bloquea **IPv4**; sesiones con origen IPv6 no son procesadas.
- No reemplaza el parche: si el servidor sigue vulnerable, el atacante puede rotar IPs.
- El IOC depende del formato actual de los archivos `raw` de cPanel; cambios futuros en cPanel pueden requerir actualizar el patrón.
- Bloqueo automático puede afectar a proxies o NAT compartidos; revisar `csf.deny` periódicamente.

---

## Disclaimer

Este script se provee **"as-is"**, sin garantías. Probarlo en un entorno de staging antes de usarlo en producción y revisar cuidadosamente los bloqueos generados. El autor y los contribuidores no se responsabilizan por interrupciones de servicio derivadas de su uso.

---

## Contribuciones

Pull requests, issues y sugerencias de mejora son bienvenidos.
