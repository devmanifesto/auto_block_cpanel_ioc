# 🚨 cPanel WHM IOC Auto Blocker

Script de seguridad para detectar y bloquear automáticamente intentos de explotación contra **WHM (cpsrvd)** en servidores cPanel.

---

## 🧠 ¿Qué hace?

Este script analiza los archivos de sesión de cPanel en:
/var/cpanel/sessions/raw/


y detecta patrones específicos de ataque asociados a intentos de explotación **pre-auth** contra WHM.

Cuando detecta un patrón válido, automáticamente:

- 🔍 Identifica la IP atacante  
- 🚫 Bloquea la IP con CSF  
- 📝 Registra el evento en logs  

---

## 🎯 ¿Qué detecta exactamente?

El script bloquea únicamente cuando se cumplen TODAS estas condiciones:

- `token_denied` presente  
- `cp_security_token` con `/cpsess`  
- `app=whostmgrd`  
- `method=badpass`  

👉 Esto corresponde a intentos de:

- Token injection  
- Bypass de autenticación  
- Exploits pre-login contra WHM  

---

## ⚠️ Importante

Este patrón **NO corresponde a actividad normal**, a diferencia de:

- expiración de sesiones  
- errores de login comunes  
- uso de webmail  

👉 Por eso el script evita falsos positivos.

---

## ⚙️ Requisitos

- Servidor con **cPanel/WHM**
- **CSF (ConfigServer Firewall)** instalado
- Acceso root

---

## 📦 Instalación

Clonar o descargar el script:
https://github.com/devmanifesto/auto_block_cpanel_ioc/blob/main/auto_block_cpanel_ioc.sh


Copiar al servidor (por ejemplo a `/root/`):

chmod +x /root/auto_block_cpanel_ioc.sh

▶️ Ejecución manual
/root/auto_block_cpanel_ioc.sh
📄 Logs

Los eventos se registran en:

/var/log/auto_block_cpanel_ioc.log

Ver últimos eventos:

tail -100 /var/log/auto_block_cpanel_ioc.log
🔍 Ver IPs bloqueadas
grep "cPanel WHM badpass cpsess IOC" /etc/csf/csf.deny
🔓 Desbloquear IP
csf -dr IP

Ejemplo:

csf -dr 68.210.120.100
🛡️ Recomendaciones adicionales

Para una mejor protección:

Activar cPHulk
Restringir acceso a WHM por IP
Mantener cPanel actualizado
Monitorear /usr/local/cpanel/logs/login_log
🚨 Disclaimer

Este script se provee "as-is" y debe ser probado antes de su uso en producción.

🤝 Contribuciones

Pull requests, mejoras y sugerencias son bienvenidas.
