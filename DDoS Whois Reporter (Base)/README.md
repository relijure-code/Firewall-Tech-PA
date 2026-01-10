[![Ver demo de la versión completa en YouTube](https://img.youtube.com/vi/x-UUYQJ_dWk/maxresdefault.jpg)](https://www.youtube.com/watch?v=x-UUYQJ_dWk)
Pronto disponible para descarga!

## DDoS Whois Reporter (Base)
Herramienta ligera para **extraer IPs relacionadas a eventos de DDoS / anomalías / cuarentena** desde un **FortiGate** vía **SSH automatizado con Plink (PuTTY)** y exportarlas a un **TXT** listo para revisión o bloqueo.

> ✅ Ideal para respuesta rápida: obtén la lista, revísala y decide qué bloquear.
> ⚠️ Siempre valida antes de aplicar cambios en firewall.

---

## 🚀 Qué hace
- Se conecta a tu FortiGate por SSH usando **plink.exe**.
- Ejecuta un comando de diagnóstico (por defecto orientado a listas tipo *quarantine/anomaly*).
- Extrae IPs del output y genera un archivo de texto con los resultados.
- (Opcional) Enriquecimiento tipo Whois/RDAP para contexto (ASN/Org), según versión del script base.

---

## 🧩 Requisitos
- **Windows**
- **Python 3.10+** (si lo ejecutas como `.py`)
- **Plink (PuTTY)**  
  - El proyecto usa `plink/plink.exe` dentro del paquete (o puedes apuntar al tuyo).
- Acceso SSH al FortiGate (host, puerto, usuario, password / token).

---

## 🛠️ Instalación (rápida)
1. Descarga el repo.
2. Verifica que exista esta ruta:
   - `.\plink\plink.exe`
3. Instala dependencias (si aplica):
   ```bash
   pip install -r requirements.txt
▶️ Uso

Ejecuta el script:
python ddos_whois_reporter_(base).py

Completa:
Host / Puerto
Usuario
Password / Token
Comando (si tu FortiGate usa un comando diferente)
Ejecuta y exporta.

📄 Archivos de salida
Según configuración, el script puede generar:
lista_de_IP.txt → lista final de IPs detectadas
adguardipblock.txt → formato blocklist estilo AdGuard (si está activo)
asn_list.txt → resumen de ASN/Org (si está activo)

⚠️ Nota importante (seguridad operativa)
Este Base es una edición simple. No incorpora todas las protecciones avanzadas contra errores humanos o listas peligrosas.

👉 Recomendación fuerte: Nunca bloquees entradas tipo:
0.0.0.0/0 (bloqueo total)
redes internas/gestión (VPN, SD-WAN, IPs de administración)
rangos críticos del negocio

⭐ Versión completa: DDoS WhoIs Plus

La edición Plus incluye seguridad y UX reforzados (OWASP/ASVS), gestión de llaves (Trust Host), exclusiones “no bloquear jamás”, bloqueo de GUI durante ejecución y más.



---

## 🇺🇸 English

```md
# DDoS Whois Reporter (Base)

A lightweight tool to **extract IPs related to DDoS / anomaly / quarantine events** from a **FortiGate** using **SSH automation with Plink (PuTTY)** and export them to a **TXT** file for review or blocking.

> ✅ Great for fast incident response: pull the list, review it, then decide what to block.
> ⚠️ Always validate before applying changes on the firewall.

---

## 🚀 What it does
- Connects to FortiGate via SSH using **plink.exe**.
- Runs a diagnostic command (default oriented to *quarantine/anomaly* style lists).
- Extracts IPs from the output and exports a clean text file.
- (Optional) RDAP/Whois enrichment for ASN/Org context, depending on the base script configuration.

---

## 🧩 Requirements
- **Windows**
- **Python 3.10+** (if running `.py`)
- **Plink (PuTTY)**
  - The repo expects `plink/plink.exe` inside the package (or you can point to your own).
- SSH access to FortiGate (host, port, username, password / token).

---
## 🛠️ Quick install
1. Download/clone the repo.
2. Make sure this path exists:
   - `.\plink\plink.exe`
3. Install dependencies (if applicable):
   ```bash
   pip install -r requirements.txt
Usage

Run:
python ddos_whois_reporter.py
Fill in:
Host / Port
Username
Password / Token
Command (if your FortiGate uses a different one)
Run and export.

📄 Output files
Depending on configuration, the tool can generate:
lista_de_IP.txt → final list of detected IPs
adguardipblock.txt → AdGuard-style blocklist format (if enabled)
asn_list.txt → ASN/Org summary (if enabled)

⚠️ Operational safety note
This Base edition is intentionally simple and does not include all the advanced guardrails against human error or dangerous entries.

👉 Strong recommendation: never block entries such as:
0.0.0.0/0 (global block)
internal/management networks (VPN, SD-WAN, admin IP ranges)
business-critical ranges

⭐ Full version: DDoS WhoIs Plus
The Plus edition adds OWASP/ASVS security + UX hardening, Trust Host key management, “never block” exclusions, GUI locking during execution, and more.
