
#!/usr/bin/env python3
"""
termTools - Herramientas ligeras para Termux (sin root) para mapear
la arquitectura básica de una red a partir de una IP objetivo.

Características principales:
- Descubrir hosts en una subred (por defecto /24) usando TCP connect (no ICMP).
- Sondar puertos TCP comunes y recolectar banners (HTTP HEAD, banner TCP simple).
- Integración opcional con `nmap` si está instalado (verificación, no obligatoria).
- Consultas pasivas a ipinfo.io (si está disponible) para enriquecer informes.
- Generación de informes JSON y CSV.

Diseñado para Termux sin root: no requiere raw sockets ni privilegios especiales.
Usar solo en redes con autorización.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import ipaddress
import socket
import json
import csv
import shutil
import urllib.request
import urllib.error
import sys
import time

# Puertos por defecto a sondear
DEFAULT_TCP_PORTS = [22,23,80,443,554,8000,8080,8443,9090]
SOCKET_TIMEOUT = 1.0
SAFE_MODE = False

def detect_subnet_from_ip(ip):
    """Asume /24 sobre la IP dada y devuelve un objeto ip_network."""
    try:
        net = ipaddress.ip_network(ip + "/24", strict=False)
        return net
    except Exception:
        return None

def tcp_host_up(host, ports=(80,443,22), timeout=SOCKET_TIMEOUT):
    """Determina si un host responde intentando conexiones TCP a puertos "comunes".
    No usa ICMP para evitar requerir privilegios.
    """
    if SAFE_MODE:
        return False
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                return True
        except Exception:
            continue
    return False

def grab_banner(host, port, timeout=SOCKET_TIMEOUT):
    """Intentar obtener un banner desde un puerto TCP. Para HTTP intenta HEAD.
    Retorna cadena (posiblemente vacía).
    """
    if SAFE_MODE:
        return ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if port in (80,8080,8000,8443,443):
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            except Exception:
                pass
        data = b""
        try:
            data = s.recv(2048)
        except Exception:
            pass
        s.close()
        return data.decode(errors='ignore').strip()
    except Exception:
        return ""

def scan_host_tcp(host, ports):
    """Escanea puertos TCP en `ports` para `host`. Retorna lista de dicts.
    Cada entrada: {port, open:bool, banner:str}
    """
    results = []
    if SAFE_MODE:
        for p in ports:
            results.append({"port": p, "open": False, "banner": "simulated"})
        return results
    for p in ports:
        ok = False
        banner = ""
        try:
            with socket.create_connection((host, p), timeout=SOCKET_TIMEOUT):
                ok = True
        except Exception:
            ok = False
        if ok:
            banner = grab_banner(host, p)
        results.append({"port": p, "open": ok, "banner": banner})
    return results

def discover_hosts_in_subnet(subnet, max_workers=50):
    """Descubre hosts vivos en la subred (ip_network) usando tcp_host_up.
    Retorna lista de IPs (strings).
    """
    hosts = []
    ips = [str(ip) for ip in subnet.hosts()]
    with ThreadPoolExecutor(max_workers=min(max_workers, 200)) as ex:
        futures = {ex.submit(tcp_host_up, ip): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    hosts.append(ip)
            except Exception:
                continue
    return hosts

def ipinfo_lookup(ip, timeout=5):
    """Consulta pasiva a ipinfo.io (si está disponible)."""
    if SAFE_MODE:
        return None
    url = f"https://ipinfo.io/{ip}/json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.load(resp)
    except Exception:
        return None

def run_nmap_if_available(hosts, port_spec, out_xml="termtools_nmap.xml"):
    """Ejecuta nmap si está instalado. Retorna dict resultado (vacio si no).
    Esta función es opcional y solo se ejecuta si `nmap` existe en PATH.
    """
    if SAFE_MODE:
        return {}
    if not shutil.which("nmap"):
        return {}
    cmd = f"nmap -sV -p {port_spec} -oX {out_xml} {' '.join(hosts)}"
    try:
        import subprocess
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    except Exception:
        return {}
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(out_xml)
        root = tree.getroot()
        results = {}
        for h in root.findall('host'):
            addr = None
            for a in h.findall('address'):
                if a.get('addrtype') == 'ipv4':
                    addr = a.get('addr')
            if not addr:
                continue
            ports = []
            for p in h.findall('.//port'):
                pid = int(p.get('portid'))
                state = p.find('state').get('state') if p.find('state') is not None else 'unknown'
                serv = p.find('service')
                svc = serv.get('name') if serv is not None and 'name' in serv.attrib else ''
                ver = (serv.get('product','') + ' ' + serv.get('version','')).strip() if serv is not None else ''
                ports.append({'port': pid, 'state': state, 'service': svc, 'version': ver})
            results[addr] = ports
        return results
    except Exception:
        return {}

def save_reports(result_dict, out_json='termtools_report.json', out_csv='termtools_report.csv'):
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(result_dict, f, indent=2, ensure_ascii=False)
    rows = []
    for host, info in result_dict.items():
        for svc in info.get('services', []):
            rows.append({'host': host, 'port': svc.get('port'), 'open': svc.get('open'), 'banner': svc.get('banner','')})
    if rows:
        with open(out_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['host','port','open','banner'])
            writer.writeheader()
            for r in rows:
                writer.writerow(r)

def main():
    parser = argparse.ArgumentParser(description='termTools - mapeo de red ligero para Termux (sin root)')
    parser.add_argument('--ip', help='IP objetivo (ej: 192.168.1.10)')
    parser.add_argument('--cidr', help='CIDR objetivo (ej: 192.168.1.0/24)')
    parser.add_argument('--modo-seguro', action='store_true', help='Simula acciones sin generar tráfico')
    parser.add_argument('--no-nmap', action='store_true', help='No ejecutar nmap aunque esté disponible')
    parser.add_argument('--ports', help='Puertos TCP a probar, coma-sep', default=','.join(str(p) for p in DEFAULT_TCP_PORTS))
    parser.add_argument('--out-json', default='termtools_report.json')
    parser.add_argument('--out-csv', default='termtools_report.csv')
    parser.add_argument('--threads', type=int, default=50)
    args = parser.parse_args()

    global SAFE_MODE
    SAFE_MODE = bool(args.modo_seguro)

    if not args.ip and not args.cidr:
        print('Especifica --ip o --cidr. Ejemplo: --ip 192.168.1.10')
        sys.exit(1)

    if args.cidr:
        try:
            subnet = ipaddress.ip_network(args.cidr, strict=False)
        except Exception as e:
            print('CIDR inválido:', e)
            sys.exit(1)
    else:
        subnet = detect_subnet_from_ip(args.ip)
        if not subnet:
            print('No se pudo calcular subred desde la IP proporcionada')
            sys.exit(1)

    print(f'Discovering hosts in {subnet} ...')
    hosts = discover_hosts_in_subnet(subnet, max_workers=args.threads)
    print(f'Hosts vivos detectados: {len(hosts)}')

    report = {}
    ports = [int(x) for x in args.ports.split(',') if x.strip()]

    with ThreadPoolExecutor(max_workers=min(args.threads, 200)) as ex:
        futures = {ex.submit(scan_host_tcp, h, ports): h for h in hosts}
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                services = fut.result()
            except Exception:
                services = []
            report[h] = {'services': services}
            ipinfo = ipinfo_lookup(h)
            if ipinfo:
                report[h]['ipinfo'] = ipinfo

    if not args.no_nmap and shutil.which('nmap') and not SAFE_MODE:
        print('Ejecutando nmap para verificación (si está disponible)...')
        nmap_res = run_nmap_if_available(hosts, ','.join(str(p) for p in ports))
        for h, ports in nmap_res.items():
            report.setdefault(h, {})
            report[h]['nmap'] = ports

    save_reports(report, out_json=args.out_json, out_csv=args.out_csv)
    print('Informes guardados:', args.out_json, args.out_csv)

if __name__ == '__main__':
    main()

