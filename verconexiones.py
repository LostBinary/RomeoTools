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

            # Ignorar multicast y privadas
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                continue

            if ip.startswith("224.") or ip.startswith("239."):
                continue

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

        resultado = {
            "ip": ip,
            "org": data.get("org", "Desconocido"),
            "country": data.get("country", "??"),
            "region": data.get("region", "??")
        }

        cache[ip] = resultado
        return resultado

    except:
        return {
            "ip": ip,
            "org": "Error",
            "country": "??",
            "region": "??"
        }

def main():
    print("🔍 Analizando conexiones...\n")

    lineas = obtener_conexiones()
    ips = extraer_ips(lineas)

    print(f"IPs encontradas: {len(ips)}\n")

    resultado = []

    for ip in ips:
        info = consultar_ip(ip)
        resultado.append(info)

    for r in resultado:
        print(f"{r['ip']:15} | {r['org']:<30} | {r['country']:3} | {r['region']}")

if __name__ == "__main__":
    while True:
        main()
        time.sleep(10)