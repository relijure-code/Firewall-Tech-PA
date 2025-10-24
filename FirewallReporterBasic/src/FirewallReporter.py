import wexpect
from openpyxl import Workbook
from cryptography.fernet import Fernet
import os
from collections import defaultdict
from time import sleep

# Generar clave única para cifrar contraseñas (una vez)
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Cargar clave para cifrar y descifrar
def load_key():
    return open("secret.key", "rb").read()

# Cifrar contraseña
def encrypt_password(password):
    f = Fernet(load_key())
    return f.encrypt(password.encode()).decode()

# Descifrar contraseña
def decrypt_password(encrypted_password):
    f = Fernet(load_key())
    return f.decrypt(encrypted_password.encode()).decode()

# Conexión SSH usando plink.exe con interacción paso a paso
def connect_ssh_with_interaction(host, port, username, password, token=None):
    try:
        # Ruta al ejecutable de plink
        plink_path = "plink.exe"

        # Construir el comando de conexión
        ssh_command = f"{plink_path} -ssh -P {port} -l {username} {host}"
        print("\nIntentando conectar con el siguiente comando:")
        print(ssh_command)

        # Ejecutar el comando y manejar interacción
        child = wexpect.spawn(ssh_command, timeout=60)

        # Manejar el prompt para contraseña
        child.expect("password:")
        child.sendline(password.strip())
        print("Contraseña enviada correctamente.")

        # Manejar el prompt para acceso inicial
        child.expect("Access granted. Press Return to begin session.")
        child.sendline("")  # Enviar Enter para continuar
        print("Acceso inicial concedido, enviando Enter.")

        # Manejar el prompt para token (si aplica)
        if token:
            child.expect("FortiToken:")
            child.sendline(token.strip())
            print("Token enviado correctamente.")

        # Verificar prompt final
        child.expect("#")
        print("Conexión exitosa. Sesión iniciada en el FortiGate.")

        return child

    except wexpect.wexpect_util.TIMEOUT:
        print("Error: Tiempo de espera agotado durante la conexión.")
        return None
    except wexpect.wexpect_util.EOF:
        print("Conexión terminada inesperadamente.")
        return None
    except Exception as e:
        print(f"Error al intentar conectar: {e}")
        return None

# Ejecutar comando en sesión abierta
def execute_command(session, command, progress_message):
    try:
        print(progress_message)
        session.sendline(command)
        session.expect("#", timeout=60)
        output = session.before
        if isinstance(output, bytes):
            output = output.decode()
        return output
    except wexpect.wexpect_util.TIMEOUT:
        print(f"Error: Tiempo de espera agotado al ejecutar el comando: {command}")
        return None

# Parsear y consolidar referencias
def parse_and_merge_references(references):
    merged_references = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    for objeto, reference_output in references:
        lines = reference_output.splitlines()
        for line in lines:
            if "entry used by child table" in line:
                try:
                    parts = line.split(" ")
                    field = parts[5].strip("'")  # Campo referenciado
                    table = parts[9].strip("'")  # Tabla referenciada
                    ref_name = parts[-1].strip("'")  # Referencia
                    merged_references[table][field][ref_name].add(objeto)
                except IndexError:
                    pass  # Ignorar líneas con formato inesperado
    return merged_references

# Generar el reporte consolidado
def generate_excel_report_merged(groups_references, addresses_references):
    wb = Workbook()
    sheet = wb.active
    sheet.title = "Referencias Consolidado"

    # Encabezados
    sheet.append(["Objeto(s)", "Tabla Referenciada", "Campo Referenciado", "Referencia"])

    # Combinar todas las referencias
    all_references = parse_and_merge_references(groups_references) | parse_and_merge_references(addresses_references)

    # Escribir datos consolidados en el Excel
    for table, fields in all_references.items():
        for field, refs in fields.items():
            for ref_name, objects in refs.items():
                sheet.append([", ".join(sorted(objects)), table, field, ref_name])

    # Guardar el archivo
    output_file = "referencias_firewall_consolidado.xlsx"
    wb.save(output_file)
    print(f"Reporte consolidado generado: {output_file}")

# Flujo principal
def main():
    if not os.path.exists("secret.key"):
        generate_key()
        print("Clave de cifrado generada. Ejecuta de nuevo el script.")
        exit()

    host = input("Introduce la IP del FortiGate: ")
    port = int(input("Introduce el puerto SSH (por defecto 22): ") or 22)
    username = input("Introduce tu usuario: ")
    password = input("Introduce tu contraseña: ")
    token = input("Introduce tu token de autenticación (si aplica): ") or None

    session = connect_ssh_with_interaction(host, port, username, password, token)
    if not session:
        print("No se pudo establecer conexión con el FortiGate.")
        return

    print("0% - Conexión establecida.")

    groups_output = execute_command(session, "show firewall addrgrp | grep 'edit'", "50% - Listando grupos de direcciones.")
    if not groups_output:
        print("Error al obtener los grupos de direcciones.")
        session.sendline("exit")
        return

    addresses_output = execute_command(session, "show firewall address | grep 'edit'", "75% - Listando direcciones.")
    if not addresses_output:
        print("Error al obtener las direcciones.")
        session.sendline("exit")
        return

    # Extraer nombres de objetos
    groups = [line.replace("edit", "").strip().strip('"') for line in groups_output.splitlines() if "edit" in line]
    addresses = [line.replace("edit", "").strip().strip('"') for line in addresses_output.splitlines() if "edit" in line]

    # Validar referencias de objetos
    group_references = [(group, execute_command(session, f"diag sys cmdb refcnt show firewall.addrgrp:name {group}", f"Validando grupo {group}.") or "") for group in groups]
    address_references = [(address, execute_command(session, f"diag sys cmdb refcnt show firewall.address:name {address}", f"Validando dirección {address}.") or "") for address in addresses]

    print("95% - Generando reporte consolidado.")
    generate_excel_report_merged(group_references, address_references)

    print("100% - Reporte generado. Cerrando sesión.")
    session.sendline("exit")

if __name__ == "__main__":
    main()
