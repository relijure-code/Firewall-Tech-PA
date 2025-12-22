# 🔥 Firewall Reporter Hardened v4.6 (versión con donación)

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
👉 [Ver código fuente](https://github.com/relijure-code/Firewall-Tech-PA/blob/bb4f415e08f4f7aca8a66ba2ccab25de1ee24144/FirewallReporterBasic/src/FirewallReporter.py)

---

## ⚖️ Licencia

Software con fines educativos y de auditoría interna.  
No modifica configuraciones del firewall.  
Cumple con prácticas OWASP/ASVS y se recomienda su uso bajo políticas corporativas.

© 2025 Reinaldo Juárez — *Firewall Reporter Hardened v4.6*

English
# 🔥 Firewall Reporter Hardened v4.6 (donationware)

**FortiGate inventory, dependency mapping, and policy reporting with Excel output and OWASP/ASVS-aligned controls.**  
Automate the extraction, analysis, and delivery of audit evidence from FortiGate using a secure, traceable GUI.

---

## 🚀 Key features

- **Object inventory:** `show firewall address`, `show firewall addrgrp`
- **Dependency mapping:** `diag sys cmdb refcnt`, `show firewall.address/<name>`
- **Policies:** `show firewall policy` (quick mode or full mode)
- **Excel report:** **“References (Consolidated)”** sheet with a formula to detect **ANY-TO-ANY**
- **Results output:** auto path `%APPDATA%\MiAppBin\results\YYYYMMDD_HHMMSS`
- **Audit log:** `logs\bitacora_ejecuciones.log` with timestamp, host, and output path
- **TOFU popup:** **SHA256** fingerprint + host key registration
- **Secure UX:** IP/port validation, clipboard cleanup, copy/paste blocking
- **Compatibility:** **FortiOS** (interactive shell / PTY)
- **Authentication:** SSH key (Ed25519/RSA) + passphrase, password, or OTP

---

## 🧩 Requirements

- **OS:** Windows 10/11 (x64)  
- **Runtime:** Python 3.10+  
- **Connectivity:** SSH access to FortiGate  

---

## 📊 Outputs and logs

| Type | Path |
|------|------|
| Results | `%APPDATA%\MiAppBin\results\YYYYMMDD_HHMMSS\` |
| Logs | `%APPDATA%\MiAppBin\logs\bitacora_ejecuciones.log` |
| Host keys (APP) | `%APPDATA%\MiAppBin\cfg\known_hosts` |

---

## 🆕 What’s new in v4.6

- **TOFU** popup with SHA256 fingerprint  
- **Single-run lock** + **progressive backoff**  
- **Improved Excel report** with ANY-TO-ANY detection formula  
- Audit log now includes host and output path  
- Improved FortiOS compatibility (PTY)

---

## 🛡️ OWASP / ASVS mapping

| Area | Control applied |
|------|------------------|
| V2 – Authentication | Credential protection, OTP, copy/paste blocking |
| V4 – Access control | Single session (single-run lock) |
| V5 – Input validation | IP/port validation |
| V7 – Error handling | Safe logs without secrets |
| V9 – Communications | TOFU verification + SHA256 |
| V14 – Hardening | Isolated host keys, cleanup and rotation |

---

## 📥 Download

🔗 **Full version v4.6 (.py)**  
👉 [Download on Gumroad](https://relijure.gumroad.com/l/fortigate-script-reporter)  

💡 **Base version (GitHub)**  
👉 [View source code](https://github.com/relijure-code/Firewall-Tech-PA/blob/bb4f415e08f4f7aca8a66ba2ccab25de1ee24144/FirewallReporterBasic/src/FirewallReporter.py)

---

## ⚖️ License

For educational and internal auditing use only.  
Does not modify firewall configurations.  
OWASP/ASVS-aligned; recommended to use under corporate policies.

© 2025 Reinaldo Juárez — *Firewall Reporter Hardened v4.6*

