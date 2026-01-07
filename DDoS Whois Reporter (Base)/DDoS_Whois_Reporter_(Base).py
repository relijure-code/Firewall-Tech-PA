# -*- coding: utf-8 -*-
import re
import logging
import json
import ipaddress
import os
import sys
import tkinter as tk
from tkinter import messagebox

import wexpect
from ipwhois import IPWhois
import requests  # Fallback RDAP HTTP

# ==========================
# Logging
# ==========================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==========================
# Utilidades generales
# ==========================
def get_plink_path():
    if getattr(sys, 'frozen', False):
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    plink_path = os.path.join(base_dir, "plink", "plink.exe")
    print(f"Ruta de plink.exe: {plink_path}")
    return plink_path

def load_excluded_organizations(file_path='excluded_orgs.json'):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, list):
                logging.warning("El JSON de exclusiones no es una lista; se ignorará.")
                return set()
            return set(x.lower() for x in data)
    except FileNotFoundError:
        logging.warning(f"No se encontró {file_path}. Continuando sin exclusiones.")
        return set()
    except Exception as e:
        logging.error(f"Error al cargar organizaciones excluidas: {e}")
        return set()

def is_excluded_organization(org_name: str, excluded_organizations: set) -> bool:
    org_low = (org_name or '').lower()
    return any(excl in org_low for excl in excluded_organizations)

# === Mejora #3: marcadores de registrantes genéricos ===
GENERIC_TOKENS = {'ip manager', 'noc', 'hostmaster', 'abuse', 'admin-c', 'tech-c'}

def is_generic_registrant(name: str) -> bool:
    n = (name or '').lower()
    return any(tok in n for tok in GENERIC_TOKENS)

# ==========================
# SSH FortiGate
# ==========================
def connect_ssh_with_interaction(host, port, username, password, token=None):
    plink_path = get_plink_path()
    ssh_command = f'"{plink_path}" -ssh -P {port} -l {username} {host}'
    print(f"\nIntentando conectar con el siguiente comando: {ssh_command}")
    try:
        child = wexpect.spawn(ssh_command, timeout=60)
        child.expect("password:")
        child.sendline(password.strip())
        print("Contraseña enviada correctamente.")
        child.expect("Access granted. Press Return to begin session.")
        child.sendline("")
        print("Acceso inicial concedido, enviando Enter.")
        if token:
            child.expect("FortiToken:")
            child.sendline(token.strip())
            print("Token enviado correctamente.")
        child.expect("#")
        print("Conexión exitosa. Sesión iniciada en el FortiGate.")
        return child
    except Exception as e:
        logging.error(f"Error en la conexión SSH: {e}")
        return None

def execute_command_with_paging(session, command):
    print(f"Ejecutando comando: {command}")
    session.sendline(command)
    output = ""
    while True:
        index = session.expect([r"--More--", r"#"], timeout=120)
        chunk = session.before.decode() if isinstance(session.before, bytes) else session.before
        output += chunk
        if index == 0:
            session.send("\b")
        elif index == 1:
            break
    return output

# ==========================
# RDAP / Fallback genérico
# ==========================
rdap_cache = {}  # cache global

def _fetch(url, timeout=15):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

def _fetch_rdap_http(ip: str) -> dict | None:
    """
    Intenta RDAP por HTTP:
    1) LACNIC   https://rdap.lacnic.net/rdap/ip/{ip}
    2) rdap.org https://rdap.org/ip/{ip}  (proxy multi-RIR)
    Sigue link 'self' si apunta al bloque CIDR.
    """
    endpoints = [
        f"https://rdap.lacnic.net/rdap/ip/{ip}",
        f"https://rdap.org/ip/{ip}",
    ]
    for base in endpoints:
        for attempt in range(2):
            try:
                data = _fetch(base, timeout=20 if attempt else 12)
                if isinstance(data, dict):
                    try:
                        for lk in data.get("links", []) or []:
                            if lk.get("rel") == "self" and "/rdap/ip/" in lk.get("href", ""):
                                href = lk.get("href")
                                if href and href != base:
                                    data = _fetch(href, timeout=12)
                                break
                    except Exception:
                        pass
                return data
            except Exception:
                if attempt == 1:
                    break
    return None

def _vcard_fn(entity: dict) -> str | None:
    v = entity.get("vcardArray", [])
    if isinstance(v, list) and len(v) >= 2:
        for item in v[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                name = str(item[3]).strip()
                if name:
                    return name
    return None

def _extract_registrant_from_ipwhois_result(result: dict) -> str | None:
    """Saca registrant desde 'objects' del resultado de ipwhois.lookup_rdap()."""
    if not result:
        return None
    objects = result.get("objects", {}) or {}
    for obj in objects.values():
        roles = [x.lower() for x in obj.get("roles", []) or []]
        if "registrant" in roles or "owner" in roles:
            fn = _vcard_fn(obj)
            if fn:
                return fn
    for obj in objects.values():
        fn = _vcard_fn(obj)
        if fn:
            return fn
    return None

def _extract_registrant_from_rdap(rdap_json: dict) -> str | None:
    """registrant/owner.fn → cualquier entity.fn → lacnic_legalRepresentative → name."""
    if not rdap_json:
        return None
    ents = rdap_json.get("entities", []) or []
    for ent in ents:
        roles = [x.lower() for x in ent.get("roles", []) or []]
        if "registrant" in roles or "owner" in roles:
            fn = _vcard_fn(ent)
            if fn:
                return fn
    for ent in ents:
        fn = _vcard_fn(ent)
        if fn:
            return fn
    rep = rdap_json.get("lacnic_legalRepresentative")
    if rep:
        rep = str(rep).strip()
        if rep:
            return rep
    netname = rdap_json.get("name") or rdap_json.get("network", {}).get("name")
    return str(netname).strip() if netname else None

def _extract_cidr_from_rdap(rdap_json: dict) -> str | None:
    """CIDR desde cidr0_cidrs → remarks('Network: ...') → cálculo desde start/end si es bloque exacto."""
    if not rdap_json:
        return None
    # a) Extensión cidr0
    for c in rdap_json.get("cidr0_cidrs", []) or []:
        p = c.get("v4prefix") or c.get("v6prefix")
        l = c.get("length")
        if p and l is not None:
            return f"{p}/{l}"
    # b) Remarks tipo "Network: 170.244.188.0/22"
    for rem in rdap_json.get("remarks", []) or []:
        for line in rem.get("description", []) or []:
            line = str(line)
            if "Network:" in line and "/" in line:
                cand = line.split("Network:", 1)[1].strip()
                if "/" in cand and cand.count(".") == 3:
                    return cand
    # c) startAddress/endAddress → /n si coincide con bloque exacto
    start = rdap_json.get("startAddress")
    end = rdap_json.get("endAddress")
    if start and end and all(isinstance(x, str) and x.count(".") == 3 for x in (start, end)):
        try:
            s = int(ipaddress.IPv4Address(start))
            e = int(ipaddress.IPv4Address(end))
            size = e - s + 1
            if size > 0 and (size & (size - 1)) == 0 and (s % size) == 0:
                prefix = 32 - (size.bit_length() - 1)
                return f"{start}/{prefix}"
        except Exception:
            pass
    # d) (raro) prefixLength directo
    length = rdap_json.get("prefixLength")
    if start and isinstance(length, int):
        return f"{start}/{length}"
    return None

# === Mejora #2: ASN por fallback para LACNIC (lacnic_originAutnum) ===
def _extract_asn_from_rdap(rdap_json: dict) -> str | None:
    if not rdap_json:
        return None
    arr = rdap_json.get("lacnic_originAutnum")
    if isinstance(arr, list) and arr:
        try:
            return str(arr[0]).strip()
        except Exception:
            return None
    return None

def check_ip_in_lacnic(ip, excluded_organizations):
    """
    Devuelve (cidr, asn, organization, is_excluded)
    1) ipwhois.lookup_rdap()
    2) Fallback RDAP HTTP (LACNIC → rdap.org)
    + ASN fallback desde lacnic_originAutnum si falta
    """
    if ip in rdap_cache:
        return rdap_cache[ip]

    used_fallback = False
    registrant_seen = None

    try:
        ipwhois = IPWhois(ip)
        result = ipwhois.lookup_rdap()

        cidr = result.get('network', {}).get('cidr', 'N/A')
        asn = result.get('asn', 'N/A')
        organization = result.get('network', {}).get('name', 'N/A')

        # Rellena org desde objects si falta
        if not organization or organization == 'N/A':
            from_objects = _extract_registrant_from_ipwhois_result(result)
            if from_objects:
                organization = from_objects

        # Fallback HTTP si sigue faltando org/cidr/asn
        rdap_json = None
        if (not organization or organization == 'N/A') or (not cidr or cidr == 'N/A') or (asn in (None, 'N/A', 'Error')):
            rdap_json = _fetch_rdap_http(ip)

        if rdap_json:
            registrant = _extract_registrant_from_rdap(rdap_json)
            registrant_seen = registrant
            if (not organization or organization == 'N/A') and registrant:
                organization = registrant
                used_fallback = True
            if (not cidr or cidr == 'N/A'):
                cidr_http = _extract_cidr_from_rdap(rdap_json)
                if cidr_http:
                    cidr = cidr_http
                    used_fallback = True
            # Mejora #2: ASN desde lacnic_originAutnum si no lo teníamos
            if (asn in (None, 'N/A', 'Error')):
                asn_http = _extract_asn_from_rdap(rdap_json)
                if asn_http:
                    asn = asn_http
                    used_fallback = True

        is_excluded = is_excluded_organization(organization or 'N/A', excluded_organizations)
        rdap_cache[ip] = (cidr if cidr else 'Error',
                          asn if asn else 'Error',
                          organization if organization else 'N/A',
                          is_excluded)

        if used_fallback:
            logging.info(f"[FALLBACK] {ip} → registrant='{registrant_seen}' cidr='{rdap_cache[ip][0]}' asn='{rdap_cache[ip][1]}'")
        return rdap_cache[ip]

    except Exception as e:
        logging.debug(f"lookup_rdap() falló para {ip}: {e}")
        rdap_json = _fetch_rdap_http(ip)
        registrant = _extract_registrant_from_rdap(rdap_json) if rdap_json else None
        cidr_http = _extract_cidr_from_rdap(rdap_json) if rdap_json else None
        asn_http = _extract_asn_from_rdap(rdap_json) if rdap_json else None

        cidr = cidr_http if cidr_http else 'Error'
        asn = asn_http if asn_http else 'Error'
        organization = registrant if registrant else 'N/A'

        is_excluded = is_excluded_organization(organization or 'N/A', excluded_organizations)
        rdap_cache[ip] = (cidr, asn, organization, is_excluded)
        logging.info(f"[FALLBACK_ERR] {ip} → registrant='{registrant}' cidr='{cidr}' asn='{asn}'")
        return rdap_cache[ip]

# ==========================
# Guardado (solo NO excluidas)
# ==========================
def save_ips_in_column_format(ips_data, excluded_organizations, output_file='lista_de_IP.txt'):
    """CIDR de NO excluidas; descarta 'Error'."""
    try:
        saved = 0
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip, cidr, asn, organization in ips_data:
                if cidr != 'Error' and not is_excluded_organization(organization, excluded_organizations):
                    for cidr_block in cidr.split(','):
                        f.write(f"{cidr_block.strip()}\n")
                        saved += 1
        print(f"Lista de CIDR guardada en formato columna en {output_file}. (líneas: {saved})")
    except Exception as e:
        print(f"Error al guardar los CIDR: {e}")

def save_asns_in_file(ips_data, excluded_organizations, output_file='asn_list.txt'):
    """Solo NO excluidas y ASN válido."""
    try:
        saved = 0
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip, cidr, asn, organization in ips_data:
                if asn != 'Error' and not is_excluded_organization(organization, excluded_organizations):
                    f.write(f"{ip} {cidr} {asn} {organization}\n")
                    saved += 1
        print(f"Lista de ASN guardada en formato columna en {output_file}. (líneas: {saved})")
    except Exception as e:
        print(f"Error al guardar los ASN: {e}")

# === Mejora #1: AdGuard sin depender de CIDR (bloquea IP aunque CIDR sea 'Error')
def save_ips_in_adguard_format(ips_data, excluded_organizations, output_file='adguardipblock.txt'):
    """Guarda TODAS las IP NO excluidas (independiente de CIDR)."""
    try:
        saved = 0
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip, cidr, asn, organization in ips_data:
                if not is_excluded_organization(organization, excluded_organizations):
                    f.write(f"{ip}$network\n")
                    saved += 1
        print(f"Lista de IPs en formato AdGuard guardada en {output_file}. (líneas: {saved})")
    except Exception as e:
        print(f"Error al guardar las IPs en formato AdGuard: {e}")

# ==========================
# Flujo principal
# ==========================
def process_ips(host, port, username, password, token):
    excluded_organizations = load_excluded_organizations()

    session = connect_ssh_with_interaction(host, port, username, password, token)
    if not session:
        messagebox.showerror("Error", "No se pudo conectar al firewall.")
        return

    quarantine_output = execute_command_with_paging(session, "diagnose user quarantine list")
    session.sendline("exit")

    ips_from_firewall = re.findall(r'(\d+\.\d+\.\d+\.\d+)', quarantine_output)
    print(f"IPs extraídas del firewall: {ips_from_firewall}")

    if not ips_from_firewall:
        messagebox.showinfo("Información", "No se encontraron IPs en cuarentena.")
        return

    ips_data = []
    total = total_excluidas = total_guardadas = total_invalidas = 0

    for ip in ips_from_firewall:
        total += 1
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logging.warning(f"IP inválida: {ip}")
            total_invalidas += 1
            continue

        cidr, asn, organization, is_excluded = check_ip_in_lacnic(ip, excluded_organizations)

        # Mejora #3: marcar genéricos en la impresión
        flag = " ⚠️GENÉRICO" if is_generic_registrant(organization) else ""
        print(f"[RESUELTA] {ip} | CIDR:{cidr} | ASN:{asn} | ORG:{organization}{flag} | EXCLUIDA:{is_excluded}")

        if is_excluded:
            total_excluidas += 1
            logging.info(f"IP {ip} pertenece a una organización excluida: {organization}")
        else:
            ips_data.append((ip, cidr, asn, organization))
            total_guardadas += 1

    # Guardados
    save_ips_in_column_format(ips_data, excluded_organizations)
    save_asns_in_file(ips_data, excluded_organizations)
    save_ips_in_adguard_format(ips_data, excluded_organizations)

    print("\n=== RESUMEN DE EJECUCIÓN ===")
    print(f"Total extraídas:               {total}")
    print(f"Total inválidas:               {total_invalidas}")
    print(f"Total excluidas (solo log):    {total_excluidas}")
    print(f"Total no excluidas (guardadas):{total_guardadas}")

    messagebox.showinfo("Éxito", "Proceso completado correctamente.")

# ==========================
# GUI
# ==========================
def create_gui():
    def on_submit():
        host = entry_host.get()
        port = entry_port.get()
        username = entry_username.get()
        password = entry_password.get()
        token = entry_token.get()

        if not host or not port or not username or not password:
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return

        try:
            p = int(port)
        except ValueError:
            messagebox.showerror("Error", "El puerto debe ser un número.")
            return

        process_ips(host, p, username, password, token)

    root = tk.Tk()
    root.title("Automatización de cuarentena FortiGate")

    tk.Label(root, text="Host:").grid(row=0, column=0, padx=10, pady=5)
    entry_host = tk.Entry(root, width=30); entry_host.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(root, text="Puerto:").grid(row=1, column=0, padx=10, pady=5)
    entry_port = tk.Entry(root, width=10); entry_port.grid(row=1, column=1, padx=10, pady=5)

    tk.Label(root, text="Usuario:").grid(row=2, column=0, padx=10, pady=5)
    entry_username = tk.Entry(root, width=30); entry_username.grid(row=2, column=1, padx=10, pady=5)

    tk.Label(root, text="Contraseña:").grid(row=3, column=0, padx=10, pady=5)
    entry_password = tk.Entry(root, show="*", width=30); entry_password.grid(row=3, column=1, padx=10, pady=5)

    tk.Label(root, text="Token (opcional):").grid(row=4, column=0, padx=10, pady=5)
    entry_token = tk.Entry(root, show="*", width=30); entry_token.grid(row=4, column=1, padx=10, pady=5)

    tk.Button(root, text="Enviar", command=on_submit).grid(row=5, column=0, columnspan=2, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
