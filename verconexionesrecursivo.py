import subprocess
import re
import requests
import time

# Evitar repetir consultas a la misma IP
cache = {}

def obtener_conexiones():
    resultado = subprocess.check_output("netstat -ano", shell=True).decode(errors="ignore")
    return resultado.split("\n")

def extraer_ips(lineas):
    ips = set()

    for linea in lineas:
        match = re.search(r"\d+\.\d+\.\d+\.\d+:\d+\s+(\d+\.\d+\.\d+\.\d+):", linea)
        if match:
            ip = match.group(1)

            # Filtrar basura
            if not ip.startswith("127.") and not ip.startswith("0.0.0.0"):
                ips.add(ip)

    return ips

def consultar_ip(ip):
    if ip in cache:
        return cache[ip]

    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        data = r.json()

        org = data.get("org", "Desconocido")
        country = data.get("country", "??")

        resultado = (org, country)
        cache[ip] = resultado

        time.sleep(0.5)  # evitar rate limit
        return resultado

    except:
        return ("Error", "??")

def main():
    print("\n[+] Analizando conexiones...\n")

    lineas = obtener_conexiones()
    ips = extraer_ips(lineas)

    for ip in ips:
        org, country = consultar_ip(ip)
        print(f"{ip} -> {org} ({country})")

if __name__ == "__main__":
    while True:
        main()
        time.sleep(10)