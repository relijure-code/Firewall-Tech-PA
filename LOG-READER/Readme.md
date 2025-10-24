🧩 Forti Log Domain Extractor

Script en Python para leer y analizar logs de FortiGate o archivos en formato .txt y .json, identificando y agrupando dominios y subdominios válidos encontrados dentro de los registros.

Ideal para tareas de análisis de tráfico, auditorías de seguridad y clasificación de destinos en registros de red.

⚙️ Funcionalidades

Extrae dominios de URLs y textos usando expresiones regulares.

Soporta logs sin estructura (FortiGate, JSON, TXT).

Filtra TLDs válidos (.com, .net, .org, .io, etc.).

Genera un archivo resultado_agrupado.txt con los dominios únicos ordenados.

🧠 Uso

Ir al firewall FortiGate

Accede a la consola del equipo. 

![Ejecución del script](https://github.com/relijure-code/Firewall-Tech-PA/blob/a793b4eabe6a543046ac685f7651e73d3686a557/LOG-READER/images/descarga%20de%20logs.png)

Descarga el archivo de log que desees analizar (por ejemplo: traffic.log, utm.log o webfilter.log).

Colocar el log en la carpeta del script

Guarda el archivo en la misma carpeta donde está el script log_reader.py.

Renómbralo como datos.log (o ajusta el nombre dentro del script si prefieres otro).

Ejecutar el script

python log_reader.py


Resultado

Se generará automáticamente el archivo:

resultado_agrupado.txt
![Resultado](https://github.com/relijure-code/Firewall-Tech-PA/blob/7715399fd0395fd2e4443732c4277530abf47c2f/LOG-READER/images/lista-extraida.png)


con todos los dominios únicos encontrados, ordenados alfabéticamente.
