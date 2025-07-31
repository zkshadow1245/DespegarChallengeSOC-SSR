import json
import requests  # type: ignore

#Lectura del archivo .JSON
with open('alerta_av.json', 'r') as f:
    data = json.load(f)

#Extracción del Hash del archivo .JSON
hashArchivo = data['_source']['targethash']

#Variables que almacenaran la API de VirusTotal y la URL
API_KEY = 'a8314e5ef53207f042686955864e60053d59034daa5402baaf83276d4e7b29d3'  
url = f'https://www.virustotal.com/api/v3/files/{hashArchivo}'

headers = {
    'x-apikey': API_KEY
}

#Consulta mediante API
response = requests.get(url, headers=headers)
resultado = response.json()

#Imprimimos los resultados a traves de consola
print(f"HASH ANALIZADO --------> {hashArchivo}")
print(f"DETECCIONES TOTALES --------> {resultado['data']['attributes']['last_analysis_stats']['malicious']} motores lo detectaron como malicioso")
print(f"REPUTACION --------> {resultado['data']['attributes']['reputation']}")
print(f"PRIMERA VISTA --------> {resultado['data']['attributes']['first_submission_date']}")
print(f"ULTIMO ANALISIS --------> {resultado['data']['attributes']['last_analysis_date']}")