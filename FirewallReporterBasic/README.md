# 🔥 Firewall Reporter Hardened v4.6

**Inventario, dependencias y políticas de FortiGate con reporte Excel y controles OWASP/ASVS.**  
Automatiza la extracción, análisis y entrega de evidencias desde FortiGate con una GUI segura y trazable.

---

## 🚀 Características principales

- **Inventario de objetos:** `show firewall address`, `show firewall addrgrp`
- **Dependencias:** `diag sys cmdb refcnt`, `show firewall.address/<name>`
- **Políticas:** `show firewall policy` (modo rápido o completo)
- **Reporte Excel:** hoja **“Referencias Consolidado”** con fórmula para detectar **ANY-TO-ANY**
- **Gestión de resultados:** ruta automática `%APPDATA%\MiAppBin\results\YYYYMMDD_HHMMSS`
- **Bitácora:** `logs\bitacora_ejecuciones.log` con timestamp, host y ruta del archivo
- **TOFU Popup:** fingerprint **SHA256** y registro de host key
- **UX Segura:** validación de IP/puerto, limpieza de clipboard, bloqueo de copy/paste
- **Compatibilidad:** **FortiOS** (shell interactivo / PTY)
- **Autenticación:** SSH Key (Ed25519/RSA) + passphrase, password o OTP

---

## 🧩 Requisitos

- **Sistema operativo:** Windows 10/11 (x64)  
- **Lenguaje base:** Python 3.10+  
- **Conectividad:** acceso SSH al FortiGate  

---

## 📊 Resultados y bitácora

| Tipo | Ruta |
|------|------|
| Resultados | `%APPDATA%\MiAppBin\results\YYYYMMDD_HHMMSS\` |
| Logs | `%APPDATA%\MiAppBin\logs\bitacora_ejecuciones.log` |
| Host keys (APP) | `%APPDATA%\MiAppBin\cfg\known_hosts` |

---

## 🆕 Novedades v4.6

- Popup **TOFU** con fingerprint SHA256  
- **Single-run lock** y **backoff progresivo**  
- **Reporte Excel mejorado** con fórmula ANY-TO-ANY  
- Bitácora con host y ruta  
- Mayor compatibilidad con FortiOS (PTY)

---

## 🛡️ Mapeo OWASP / ASVS

| Área | Control aplicado |
|------|------------------|
| V2 – Autenticación | Protección de credenciales, OTP, bloqueo de copy/paste |
| V4 – Control de acceso | Sesión única (single-run lock) |
| V5 – Validación de entrada | Validación de IP/puerto |
| V7 – Manejo de errores | Logs seguros sin secretos |
| V9 – Comunicaciones | Verificación TOFU + SHA256 |
| V14 – Hardening | Host keys aisladas, limpieza y rotación |

---

## 📥 Descarga

🔗 **Versión completa v4.6 (.py)**  
👉 [Descargar en Gumroad](https://relijure.gumroad.com/l/fortigate-script-reporter)  


💡 **Versión base (GitHub)**  
👉 [Ver código fuente](https://github.com/relijure-code-patch-1/Firewall-Tech-PA/FirewallReporter)

---

## ⚖️ Licencia

Software con fines educativos y de auditoría interna.  
No modifica configuraciones del firewall.  
Cumple con prácticas OWASP/ASVS y se recomienda su uso bajo políticas corporativas.

© 2025 Reinaldo Juárez — *Firewall Reporter Hardened v4.6*
