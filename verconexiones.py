import subprocess
import re
import requests
import time
from collections import defaultdict

# API (puedes cambiarla si quieres más precisión)
API_URL = "https://ipinfo.io/{}/json"

def get_connections():
    """Obtiene conexiones activas usando netstat"""
    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
    return result.stdout

def extract_ips(netstat_output):
    """Extrae IPs remotas únicas"""
    ips = set()

    for line in netstat_output.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            remote = parts[2]

            # Extraer IP sin puerto
            match = re.match(r"([\d\.]+):\d+", remote)
            if match:
                ip = match.group(1)
                # Ignorar multicast y privadas
                if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                    continue

                if ip.startswith("224.") or ip.startswith("239."):
                    continue
                
                # Filtrar IPs locales
                if not ip.startswith("127.") and not ip.startswith("0.0.0.0"):
                    ips.add(ip)

    return ips

cache = {}

def get_ip_info(ip):
    if ip in cache:
        return cache[ip]

    try:
        response = requests.get(API_URL.format(ip), timeout=3)
        data = response.json()

        info = {
            "ip": ip,
            "org": data.get("org", "Desconocido"),
            "country": data.get("country", "??")
        }

        cache[ip] = info
        return info

    except:
        return {
            "ip": ip,
            "org": "Error",
            "country": "??"
        }

def main():
    print("🔍 Analizando conexiones...\n")

    netstat_output = get_connections()
    ips = extract_ips(netstat_output)

    print(f"IPs encontradas: {len(ips)}\n")

    results = []

    for ip in ips:
        info = get_ip_info(ip)
        results.append(info)

    # Mostrar resultados ordenados
    for r in results:
        print(f"{r['ip']:15} | {r['country']:3} | {r['org']}")

if __name__ == "__main__":
    while True:
        main()
        time.sleep(10)