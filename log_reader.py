import json
import re

# TLDs válidos
tlds_validos = {'.com', '.net', '.org', '.edu', '.gov', '.mil', '.int', '.biz', '.info', '.name', '.io', '.network', '.cc'}

# Función para obtener el nombre base del dominio si tiene un TLD válido
def obtener_base(dominio):
    partes = dominio.split('.')
    tld = '.' + partes[-1]  # TLD con el punto (ej: '.com')
    if tld in tlds_validos:  # Verifica si el TLD es válido
        if len(partes) > 4:
            return f"{partes[-2]}.{partes[-1]}"
        else:
            return dominio
    return None

# Función para extraer dominios con regex de un contenido de texto
def extraer_dominios(contenido):
    # Expresión regular para extraer dominios de URLs y campos de texto
    patron = r'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    coincidencias = re.findall(patron, contenido)

    # Extrae los dominios encontrados (los grupos de regex)
    dominios_encontrados = set()
    for url, host in coincidencias:
        dominio = url if url else host
        base_dominio = obtener_base(dominio)
        if base_dominio:
            dominios_encontrados.add(base_dominio)
    return dominios_encontrados

# Cargar el contenido de un archivo JSON no estructurado
archivo_entrada = 'datos.log'  # Cambia el nombre del archivo según sea necesario
with open(archivo_entrada, 'r', encoding='utf-8') as f:
    contenido_json = f.read()

# Extrae y organiza los dominios
dominios_unicos = extraer_dominios(contenido_json)

# Exporta el resultado a un archivo .txt
with open('resultado_agrupado.txt', 'w') as archivo:
    for dominio in sorted(dominios_unicos):
        archivo.write(dominio + '\n')

print("Archivo 'resultado_agrupado.txt' creado con éxito.")
