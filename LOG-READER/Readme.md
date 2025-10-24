🧩 Forti Log Domain Extractor

Script en Python para leer y analizar logs de FortiGate o archivos en formato .txt y .json, identificando y agrupando dominios y subdominios válidos encontrados dentro de los registros.

Ideal para tareas de análisis de tráfico, auditorías de seguridad y clasificación de destinos en registros de red.

⚙️ Funcionalidades

Extrae dominios de URLs y textos usando expresiones regulares.

Soporta logs sin estructura (FortiGate, JSON, TXT).

Filtra TLDs válidos (.com, .net, .org, .io, etc.).

Genera un archivo resultado_agrupado.txt con los dominios únicos ordenados.

💡 Uso

Coloca tu archivo de log (.log, .txt o .json) en el mismo directorio, nómbralo datos.log, y ejecuta:

python log_reader.py


El resultado se guardará en resultado_agrupado.txt.
