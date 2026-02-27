#!/usr/bin/env python3
"""
RomeoTools - conjunto de utilidades defensivas para auditoría de red y OSINT pasivo.

Descripción general:
- Detección de hosts en subred (ping sweep).
- Sondeo de puertos TCP/UDP y recolección de banners.
- Verificación de streams RTSP mediante ffprobe.
- Integración pasiva con APIs OSINT (ipinfo, Shodan si se configura la clave).
- Uso de nmap como verificación opcional cuando está instalado.

Uso responsable:
Ejecuta este script solo en redes/equipos para los que tengas autorización.
"""
import argparse
import ipaddress
import platform
import subprocess
import socket
import sys
import csv
import json
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
import logging
import urllib.request
import urllib.error

# ---------------- Config general ----------------
DEFAULT_TCP_PORTS = [21,22,23,25,53,80,81,88,110,111,123,135,137,138,139,143,161,179,389,443,445,554,631,636,8000,8080,8443,8554,9000,9090,37777,5000]
DEFAULT_UDP_PORTS = [53,67,68,69,123,161,500,4500]
RTSP_PORTS_TO_TRY = [554,8554,80,8080,8000,37777,5000]
RTSP_PATTERNS = [
    "/",
    "/stream",
    "/stream1",
    "/h264",
    "/ch0_0.h264",
    "/live",
    "/live.sdp",
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/media.smp",
    "/videoMain",
    "/video1",
    "/0",
    "/1",
]
RTSP_CREDENTIALS = [
    ("", ""),
    ("admin","admin"),
    ("admin","123456"),
    ("admin","888888"),
    ("admin","000000"),
    ("root","root"),
    ("user","user"),
]
SOCKET_TIMEOUT = 1.0
UDP_TIMEOUT = 1.0
PING_TIMEOUT = 1
MAX_THREADS = 20
OUT_CSV = "resultados_scaner.csv"
OUT_JSON = "resultados_scaner.json"
# Modo seguro: si es True se simulan las operaciones de red (dry-run).
# Esto permite revisar resultados y probar el flujo sin generar tráfico de red.
SAFE_MODE = False
# -------------------------------------------------

# -----------------------------------------------------------------
    
# Configuración básica de logging: salida a archivo y consola
LOG_FILE = "rometools.log"
logger = logging.getLogger("RomeoTools")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s') 
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)
# Documentación y objetivos (en español):
# Este script ofrece utilidades defensivas para:
# - Detectar hosts activos en una subred (ping sweep).
# - Sondear puertos TCP/UDP y recolectar banners (conexiones seguras limitadas).
# - Verificar servicios RTSP mediante `ffprobe` (si está disponible).
# - Usar `nmap` como verificación externa (si está instalado).
# - Aplicar una heurística básica para identificar cámaras IP (solo a modo
#   informativo, no intrusivo) y generar reportes CSV/JSON.
#
# Recomendaciones legales y éticas:
# - Ejecuta este script únicamente en redes y equipos sobre los que tengas
#   autorización explícita para realizar pruebas de seguridad.
# - Usa la opción `--modo-seguro` para simular las pruebas sin realizar
#   operaciones de red.
# -----------------------------------------------------------------

def detect_local_subnet():
    logger.info("Se realizará un escaneo de red actual... buscando hosts")
    try:
        logger.info("Detectando subred local...")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        logger.info(f"IP local detectada: {local_ip}")
        s.close()
        logger.info("Asumiendo máscara /24 para la subred local...")
        logger.info(f"Subred calculada: {local_ip}/24")
        return str(ipaddress.ip_network(local_ip + "/24", strict=False))
    except Exception:
        logger.exception("No se pudo detectar la subred local automáticamente.")
        return None

def run_cmd(cmd, timeout=5):
    # Ejecuta un comando externo de forma segura.
    # Si el modo seguro está activo, se simula la ejecución y no se toca el sistema.
    """Ejecuta un comando del sistema y devuelve (rc, stdout, stderr).

    Cuando SAFE_MODE está activado, solo se simula la ejecución y se devuelve éxito
    sin salida.
    """
    if SAFE_MODE:
        logger.info(f"[modo seguro] Simulando ejecución de comando: {cmd}")
        return 0, "", ""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, shell=False)
        logger.debug(f"run_cmd stdout(len)={len(proc.stdout)} stderr(len)={len(proc.stderr)} rc={proc.returncode}")
        return proc.returncode, proc.stdout.decode(errors="ignore"), proc.stderr.decode(errors="ignore")
    except Exception as e:
        logger.exception(f"run_cmd error: {e}")
        return 1, "", str(e)

def ping_host(ip):
    """Realiza un ping simple a la dirección IP usando la utilidad nativa.

    Devuelve True si el host responde al ping, False en caso contrario o en modo seguro.
    """
    system = platform.system()
    logger.debug(f"Sistema operativo detectado: {system}")
    if system == "Windows":
        logger.info("Detectado Windows, usando herramientas nativas...")
        logger.warning("Nota: En Windows el ping puede requerir privilegios elevados. Ejecutar terminal como administrador si es necesario.")
        cmd = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT*1000)), ip]
    else:
        logger.info("Detectado Unix-Linux, usando herramientas nativas...")
        logger.warning("Nota: En Linux el ping puede requerir privilegios elevados. Ejecutar terminal como root o con sudo si es necesario.")
        cmd = ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip]
    if SAFE_MODE:
        logger.info(f"[modo seguro] Simulando ping a {ip}")
        return False
    rc, _, _ = run_cmd(cmd, timeout=PING_TIMEOUT+1)
    logger.info(f"Resultado del ping a {ip}: rc={rc}")
    return rc == 0
    print(f"[=] Ping a {ip} {'exitoso' if rc==0 else 'fallido'}")

def arp_table_hosts():
    """Obtener entradas de la tabla ARP local.

    Devuelve una lista de diccionarios con keys: ip, mac, raw.
    """
    # parse 'arp -a' output
    try:
        logger.info("Obteniendo tabla ARP local")
        rc, out, err = run_cmd(["arp", "-a"], timeout=3)
        logger.info(f"Resultado de la tabla ARP: rc={rc}, err={err.strip()}")
        if rc != 0:
            logger.warning("No se pudo obtener la tabla ARP.")
            return []
    except Exception:
        print("[!] No se pudo ejecutar el comando arp.")
        return []
    entries = []
    if not out:
        logger.info("La tabla ARP está vacía.")
        return entries
    for line in out.splitlines():
        logger.debug(f"Procesando línea de tabla ARP: {line}")
        line = line.strip()
        if not line:
            logger.debug("Línea vacía, saltando...")
            continue
        ip = None
        mac = None
        parts = line.split()
        for p in parts:
            logger.debug(f"Analizando token ARP: {p}")
            if p.startswith("(") and p.endswith(")"):
                ip = p.strip("()")
                logger.debug(f"Encontrada posible IP: {ip}")
            if (":" in p or "-" in p) and len(p) >= 7:
                mac = p.replace("-", ":")
                logger.debug(f"Encontrada posible MAC: {mac}")
        if not ip:
            logger.debug("Intentando otro formato de parsing de la línea ARP")
            for p in parts:
                logger.debug(f"Token alternativo ARP: {p}")
                if p.count(":") == 5 and len(p) >= 14:
                    mac = p
                if p.count(".") == 3 and len(p) <= 15:
                    ip = p
        if ip:
            logger.debug(f"IP detectada: {ip}")
        if mac:
            logger.debug(f"MAC detectada: {mac}")
        if ip and mac: 
            entries.append({"ip": ip, "mac": mac, "raw": line})
            logger.info(f"Detectada ip {ip} con mac {mac}")
    return entries

def is_port_open_tcp(host, port, timeout=SOCKET_TIMEOUT):
    """Comprobar si un puerto TCP está abierto mediante conexión TCP directa.

    Retorna True si la conexión TCP se establece correctamente.
    """
    logger.debug(f"Probando puerto TCP {port} en {host}...")
    if SAFE_MODE:
        logger.info(f"[modo seguro] Simulando comprobación TCP {host}:{port}")
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            logger.info(f"Puerto TCP {port} abierto en {host}")
            return True
    except Exception:
        logger.debug(f"Puerto TCP {port} cerrado en {host}")
        return False

def grab_banner_tcp(host, port, timeout=SOCKET_TIMEOUT):
    """Intentar obtener un banner simple desde un puerto TCP.

    Envía una petición mínima (ej: HEAD para HTTP) y lee hasta 2048 bytes.
    """
    logger.debug(f"Obteniendo banner TCP de {host}:{port}...")
    if SAFE_MODE:
        logger.info(f"[modo seguro] Simulando obtención de banner para {host}:{port}")
        return ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        logger.debug(f"Conectado a {host}:{port}, enviando datos de prueba...")
        if port in (80,8080,8000,8443,554):
            logger.debug("Puerto HTTP/RTSP detectado, enviando petición HEAD...")
            try:
                logger.debug("Enviando HEAD / HTTP/1.0")
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass
            logger.debug("Esperando respuesta...")
        data = b""
        logger.debug("Recibiendo datos...")
        try:
            data = s.recv(2048)
            logger.debug(f"Recibidos {len(data)} bytes")
        except Exception:
            logger.exception("Error al recibir datos")
            pass
        s.close()
        logger.debug("Conexión cerrada")
        if data:
            logger.debug(f"Banner recibido: {data[:100]!r}")
            st = data.decode(errors="ignore").strip()
            logger.debug(f"Banner decodificado: {st}")
            st = " ".join(st.split())
            logger.debug(f"Banner limpiado: {st}")
            return st[:800]
        logger.debug("No se recibió ningún banner")
        return ""
    except Exception:
        logger.exception("Error al obtener el banner")
        return ""

def udp_probe(host, port, timeout=UDP_TIMEOUT):
    """Enviar un paquete UDP de prueba y esperar una respuesta (si la hay).

    Retorna (ok:bool, note:str).
    """
    logger.debug(f"Probando puerto UDP {port} en {host}...")
    if SAFE_MODE:
        logger.info(f"[modo seguro] Simulando probe UDP {host}:{port}")
        return False, "simulated"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        pkt = b"\x00"
        logger.debug(f"Enviando paquete UDP de prueba a {host}:{port}: {pkt!r}")
        try:
            sock.sendto(pkt, (host, port))
            logger.debug("Paquete enviado, esperando respuesta...")
        except Exception:
            logger.exception("Error al enviar el paquete UDP")
            sock.close()
            return False, "send-failed"
        try:
            logger.debug("Esperando respuesta UDP...")
            data, addr = sock.recvfrom(2048)
            logger.info(f"Respuesta UDP recibida de {addr}: len={len(data)}")
            sock.close()
            return True, f"recv_len={len(data)}"
        except socket.timeout:
            logger.debug("Timeout esperando respuesta UDP")
            sock.close()
            return False, "no-reply"
        except Exception as e:
            logger.exception(f"Error al recibir respuesta UDP: {e}")
            sock.close()
            return False, f"err:{e}"
    except Exception as e:
        logger.exception(f"Error al probar puerto UDP {port} en {host}: {e}")
        return False, f"err:{e}"

def run_nmap(hosts, port_spec, nmap_args="-sS -sV -Pn", out_xml="nmap_verif.xml"):
    logger.info(f"[*] Ejecutando nmap en hosts: {hosts} con puertos: {port_spec}")
    if SAFE_MODE:
        logger.info("[modo seguro] Simulando ejecución de nmap (no se ejecutará).")
        return {}
    if not shutil.which("nmap"):
        logger.warning("[!] nmap no encontrado en PATH, saltando escaneo nmap.")
        return {}
    hosts_str = " ".join(hosts)
    logger.info(f"[*] Hosts a escanear: {hosts_str}")
    cmd = f"nmap {nmap_args} -p {port_spec} -oX {out_xml} {hosts_str}"
    logger.info(f"[*] Ejecutando nmap sobre {hosts_str}")
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        logger.info(f"[*] nmap terminado con rc={proc.returncode}")
    except subprocess.TimeoutExpired:
        logger.warning("[!] nmap timeout")
        return {}
    results = {}
    logger.info(f"[*] Parseando resultados nmap desde {out_xml}...")
    try:
        logger.debug("[*] Leyendo archivo XML de nmap...")
        tree = ET.parse(out_xml)
        root = tree.getroot()
        for h in root.findall("host"):
            addr = None
            for a in h.findall("address"):
                logger.debug(f"[*] Procesando dirección: {a.attrib}")
                if a.get("addrtype") == "ipv4":
                    addr = a.get("addr")
                    logger.info(f"[=] Dirección IPv4 detectada: {addr}")
            if not addr:
                logger.debug("[!] No se encontró dirección IPv4, saltando...")
                continue
            ports = []
            ports_elem = h.find("ports")
            logger.debug(f"[*] Procesando puertos para {addr}...")
            if ports_elem is None:
                logger.debug("[!] No se encontraron puertos, saltando...")
                continue
            for p in ports_elem.findall("port"):
                logger.debug(f"[*] Procesando puerto: {p.attrib}")
                pid = int(p.get("portid"))
                state = p.find("state").get("state") if p.find("state") is not None else "unknown"
                logger.info(f"[=] Puerto {pid} estado: {state}")
                serv = p.find("service")
                logger.debug(f"[*] Procesando servicio: {serv.attrib if serv is not None else 'None'}")
                svc = serv.get("name") if serv is not None and "name" in serv.attrib else ""
                ver = ""
                logger.debug(f"[=] Servicio detectado: {svc}")
                if serv is not None and "product" in serv.attrib:
                    logger.debug("[*] Obteniendo versión del servicio...")
                    ver = serv.get("product","") + " " + serv.get("version","")
                    logger.debug(f"[=] Versión detectada: {ver.strip()}")
                ports.append({"port": pid, "state": state, "service": svc, "version": ver})
                logger.info(f"[=] Puerto añadido: {pid} {state} {svc} {ver.strip()}")
            results[addr] = ports
            logger.debug(f"[=] Resultados para {addr}: {ports}")
    except Exception as e:
        logger.exception("[!] Error parsing nmap XML: {e}")
    return results

# ---------------- RTSP / ffprobe ----------------
def try_ffprobe(url, timeout=5):
    logger.info(f"Probando URL RTSP con ffprobe: {url}")
    """Probar URL RTSP usando ffprobe y devolver (ok, mensaje).

    Requiere que `ffprobe` esté en PATH. En modo seguro solo simula.
    """
    if SAFE_MODE:
        logger.info(f"[modo seguro] Simulando ffprobe para {url}")
        return False, "simulated"
    if not shutil.which("ffprobe"):
        logger.warning("ffprobe no encontrado en PATH.")
        return False, "ffprobe-not-found"
    try:
        logger.debug(f"Ejecutando ffprobe con timeout {timeout}s...")
        cmd = ["ffprobe", "-v", "error", "-timeout", str(int(timeout*1000000)), "-rtsp_transport", "tcp", "-i", url]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout+2)
        stderr = proc.stderr.decode(errors="ignore")
        ok = proc.returncode == 0 or ("Stream" in stderr) or ("Input" in stderr) or ("Video:" in stderr)
        logger.info(f"ffprobe terminado con rc={proc.returncode}, ok={ok}")
        return ok, stderr.strip().replace("\n"," ")[:600]
    except Exception as e:
        logger.exception(f"Error ejecutando ffprobe: {e}")
        return False, str(e)

def build_rtsp_urls_for_host(host, ports):
    """Construir lista de URLs RTSP con patrones comunes para un host y lista de puertos."""
    urls = []
    for port in ports:
        logger.debug(f"Construyendo URLs RTSP para {host}:{port}...")
        for p in RTSP_PATTERNS:
            logger.debug(f"Añadiendo patrón: {p}")
            if port == 554:
                logger.debug("Puerto por defecto 554, sin puerto en URL.")
                urls.append(f"rtsp://{host}{p}")
            urls.append(f"rtsp://{host}:{port}{p}")
            logger.debug(f"URL añadida: {urls[-1]}")
    return urls

def scan_rtsp_host(host, ports_to_try=None, creds=RTSP_CREDENTIALS, timeout=5, max_workers=6):
    """Probar múltiples URLs RTSP y credenciales con ffprobe en paralelo.

    Devuelve lista de resultados con campos host,url,user,pass,ok,note.
    """
    logger.info(f"Escaneando host RTSP: {host}...")
    ports = ports_to_try or RTSP_PORTS_TO_TRY
    urls = build_rtsp_urls_for_host(host, ports)
    results = []
    logger.info(f"Probando {len(urls)} URLs RTSP con {len(creds)} combinaciones de credenciales...")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        logger.debug("Iniciando pruebas concurrentes de ffprobe...")
        futures = {}
        for url in urls:
            logger.debug(f"Probando URL base: {url}")
            for user, pwd in creds:
                if user or pwd:
                    logger.debug(f"Probando con credenciales: {user}:{pwd}")
                    full = url.replace("rtsp://", f"rtsp://{user}:{pwd}@")
                    logger.debug(f"URL completa: {full}")
                else:
                    logger.debug("Probando sin credenciales.")
                    full = url
                    logger.debug(f"URL completa: {full}")
                futures[ex.submit(try_ffprobe, full, timeout)] = (full, user, pwd)
        for fut in as_completed(futures):
            logger.debug("Esperando resultado de ffprobe...")
            full, user, pwd = futures[fut]
            logger.debug(f"Resultado recibido para {full}")
            try:
                ok, note = fut.result()
            except Exception as e:
                logger.exception(f"Error en ffprobe para {full}: {e}")
                ok, note = False, str(e)
            results.append({"host": host, "url": full, "user": user, "pass": pwd, "ok": ok, "note": note})
            logger.debug(f"Resultado añadido: {results[-1]}")
            if ok:
                logger.info("Éxito detectado, deteniendo pruebas adicionales para este host.")
                # stop early on first success for host
                return results
    return results

# --------------- Heurística para detectar cámaras ---------------
CAMERA_KEYWORDS = ["onvif","camera","ipcam","h.264","h264","rtsp","dahua","hikvision","ipc","video","surveillance","nv12","g711","g726"]

def heuristic_is_camera(host_info, rtsp_hits):
    """Heurística simple para valorar si un host puede ser una cámara IP.

    Devuelve (score:int, detected:bool, reasons:list).
    """
    score = 0
    reasons = []
    # puertos de interes
    tcp_open_ports = [p["port"] for p in host_info.get("tcp",[]) if p.get("open")]
    logger.debug(f"Puertos TCP abiertos: {tcp_open_ports}")
    if any(p in tcp_open_ports for p in (554,8554,37777,5000,80,8080)):
        score += 3
        reasons.append("puertos-rtsp/http detectados")
        logger.info("Puertos de interés para cámaras detectados.")
    # banners
    banners = " ".join([p.get("banner","") or "" for p in host_info.get("tcp",[])])
    logger.debug(f"Banners combinados: {banners}")
    if any(k.lower() in banners.lower() for k in CAMERA_KEYWORDS):
        score += 3
        reasons.append("banner contiene keywords de cámara")
        logger.info("Keywords de cámara detectadas en banners.")
    # mac OUI heuristico
    mac = host_info.get("mac") or ""
    logger.debug(f"MAC address: {mac}")
    if mac and len(mac.split(":")[0])==2:
        logger.debug("MAC address presente, pero no se hace verificación OUI.")
        # not a reliable check here, but could add OUI DB later
        pass
    # RTSP hits
    if rtsp_hits:
        score += 5
        reasons.append("rtsp-responds")
        logger.info("Respuesta RTSP positiva detectada.")
    detected = score >= 4
    logger.info(f"Heurística de cámara: score={score}, detectado={detected}, razones={reasons}")
    return score, detected, reasons

# ---------------- I/O save ----------------
def save_results(results_dict, csvfile=OUT_CSV, jsonfile=OUT_JSON):
    """Guardar resultados en CSV y JSON.

    El CSV contiene filas por puerto; el JSON es el dict completo.
    """
    rows = []
    for host, info in results_dict.items():
        base = {"host": host, "mac": info.get("mac",""), "alive": info.get("alive", False), "camera_score": info.get("camera_score",0), "camera_detected": info.get("camera_detected", False)}
        logger.debug(f"Procesando resultados para {host}: {info}")
        # tcp
        for t in info.get("tcp", []):
            r = base.copy()
            r.update({"proto":"tcp","port":t["port"], "open": t.get("open", False), "banner": t.get("banner",""), "sources": ",".join(t.get("source",[]))})
            rows.append(r)
            logger.debug(f"Fila añadida: {r}")
        # udp
        for u in info.get("udp", []):
            r = base.copy()
            r.update({"proto":"udp","port":u["port"], "open": u.get("open", False), "banner": u.get("note",""), "sources": ",".join(u.get("source",[]))})
            rows.append(r)
            logger.debug(f"Fila añadida: {r}")
        # if none
        if not info.get("tcp") and not info.get("udp"):
            r = base.copy()
            r.update({"proto":"","port":"","open":"","banner":"","sources":""})
            rows.append(r)
            logger.debug(f"Fila añadida (sin puertos): {r}")
    # write csv
    with open(csvfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host","mac","alive","camera_score","camera_detected","proto","port","open","banner","sources"])
        writer.writeheader()
        logger.info("Escribiendo archivo CSV...")
        for row in rows:
            writer.writerow(row)
            logger.debug(f"Fila escrita: {row}")
    # write json
    with open(jsonfile, "w", encoding="utf-8") as f:
        json.dump(results_dict, f, indent=2, ensure_ascii=False)
        logger.info("Escribiendo archivo JSON...")
    logger.info(f"Seguardo CSV en {csvfile} y JSON en {jsonfile}")

# ----------------- Pipeline functions -----------------
def discover_hosts_from_subnet(subnet, threads=MAX_THREADS):
    """Descubrir hosts vivos en una subred mediante ping sweep paralelo.

    Limita redes muy grandes y retorna lista de IPs vivas.
    """
    ips = []
    net = ipaddress.ip_network(subnet, strict=False)
    logger.info(f"Subred {subnet} tiene {net.num_addresses} direcciones.")
    if net.num_addresses > 4096:
        raise ValueError("Network too large; choose smaller range.")
        logger.warning(f"La subred es muy grande ({net.num_addresses} direcciones), elige un rango más pequeño.")
    logger.info(f"Haciendo ping sweep en {subnet} ...")
    with ThreadPoolExecutor(max_workers=min(threads, 200)) as ex:
        futures = {ex.submit(ping_host, str(ip)): str(ip) for ip in net.hosts()}
        logger.info(f"Lanzados {len(futures)} hilos de ping...")
        for fut in as_completed(futures):
            ip = futures[fut]
            logger.debug(f"Ping completado para {ip}, obteniendo resultado...")
            try:
                ok = fut.result()
                logger.info(f"Ping a {ip} {'exitoso' if ok else 'fallido'}")
            except Exception:
                ok = False
                logger.exception(f"Error en ping a {ip}")
            if ok:
                ips.append(ip)
                logger.info(f"Host vivo detectado: {ip}")
    logger.info(f"Descubiertos {len(ips)} hosts vivos en {subnet}.")
    return ips

def scan_tcp_and_banners(hosts, tcp_ports, threads=40):
    """Escanear puertos TCP en una lista de hosts y recolectar banners.

    Retorna dict host -> lista de dicts con keys: port, open, banner, source.
    """
    results = {}
    logger.info(f"Escaneando puertos TCP en {len(hosts)} hosts...")
    def scan_host_tcp(host):
        host_tcp = []
        logger.debug(f"Escaneando host {host}...")
        for p in tcp_ports:
            ok = is_port_open_tcp(host, p, timeout=SOCKET_TIMEOUT)
            banner = ""
            sources = []
            logger.debug(f"Puerto {p} en {host} {'abierto' if ok else 'cerrado'}")
            if ok:
                banner = grab_banner_tcp(host, p, timeout=SOCKET_TIMEOUT)
                sources.append("tcp-connect")
                logger.debug(f"Banner para {host}:{p}: {banner}")
            host_tcp.append({"port": p, "open": ok, "banner": banner, "source": sources})
            logger.debug(f"Resultado añadido para {host}:{p}: open={ok}, banner={banner}, sources={sources}")
        return host_tcp
    with ThreadPoolExecutor(max_workers=min(threads, len(hosts) or 1)) as ex:
        futures = {ex.submit(scan_host_tcp, h): h for h in hosts}
        logger.info(f"Lanzados {len(futures)} hilos de escaneo TCP...")
        for fut in as_completed(futures):
            h = futures[fut]
            logger.debug(f"Escaneo TCP completado para {h}, obteniendo resultados...")
            try:
                tcp_res = fut.result()
                logger.info(f"Resultados TCP para {h}: {tcp_res}")
            except Exception:
                tcp_res = []
                logger.exception(f"Error en escaneo TCP para {h}")
            results[h] = tcp_res
            open_count = len([x for x in tcp_res if x["open"]])
            logger.info(f"{h}: TCP abiertos: {open_count}")
    return results

def scan_udp_hosts(hosts, udp_ports, threads=40):
    """Escanear puertos UDP enviando paquetes de prueba y esperando respuesta.

    Retorna dict host -> lista de dicts con keys: port, open, note, source.
    """
    results = {}
    logger.info(f"Escaneando puertos UDP en {len(hosts)} hosts...")
    def scan_host_udp(host):
        host_udp = []
        logger.debug(f"Escaneando host {host} para UDP...")
        for p in udp_ports:
            ok, note = udp_probe(host, p, timeout=UDP_TIMEOUT)
            src = ["udp-probe"] if ok else []
            host_udp.append({"port": p, "open": ok, "note": note, "source": src})
            logger.debug(f"Resultado UDP para {host}:{p}: open={ok}, note={note}, source={src}")
        return host_udp
    with ThreadPoolExecutor(max_workers=min(threads, len(hosts) or 1)) as ex:
        futures = {ex.submit(scan_host_udp, h): h for h in hosts}
        logger.info(f"Lanzados {len(futures)} hilos de escaneo UDP...")
        for fut in as_completed(futures):
            h = futures[fut]
            logger.debug(f"Escaneo UDP completado para {h}, obteniendo resultados...")
            try:
                udp_res = fut.result()
                logger.info(f"Resultados UDP para {h}: {udp_res}")
            except Exception:
                udp_res = []
                logger.exception(f"Error en escaneo UDP para {h}")
            results[h] = udp_res
            opens = len([u for u in udp_res if u["open"]])
            logger.info(f"{h}: UDP abiertos: {opens}")
            if opens:
                logger.info(f"{h}: UDP responde en puertos : {opens}")
    return results

def rtsp_phase_over_hosts(hosts, tcp_info_dict, timeout=5, max_workers=6):
    """Ejecutar fase RTSP sobre múltiples hosts en paralelo.

    Usa scan_rtsp_host internamente y agrega resultados por host.
    """
    all_rtsp_hits = {}
    logger.info(f"Ejecutando fase RTSP en {len(hosts)} hosts...")
    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts) or 1)) as ex:
        futures = {ex.submit(scan_rtsp_host, h, None, RTSP_CREDENTIALS, timeout, max_workers): h for h in hosts}
        logger.info(f"Lanzados {len(futures)} hilos de escaneo RTSP...")
        for fut in as_completed(futures):
            h = futures[fut]
            logger.debug(f"Escaneo RTSP completado para {h}, obteniendo resultados...")
            try:
                res = fut.result()
                logger.info(f"Resultados RTSP para {h}: {res}")
            except Exception as e:
                res = [{"host": h, "url": "", "user":"", "pass":"", "ok": False, "note": str(e)}]
                logger.exception(f"Error en escaneo RTSP para {h}: {e}")
            hits = [r for r in res if r.get("ok")]
            all_rtsp_hits[h] = res
            logger.info(f"{h}: RTSP hits: {len(hits)}")
            if hits:
                logger.info(f"[HIT-RTSP] {h} -> {hits[0]['url']} creds=({hits[0]['user']}:{hits[0]['pass']})")
    return all_rtsp_hits


def ensure_authorized():
    """Solicitar confirmación al operador antes de acciones activas.

    Retorna True si el usuario confirma o si SAFE_MODE está activo.
    """
    if SAFE_MODE:
        logger.info("[modo seguro] Operación en modo simulación; no se requiere autorización.")
        return True
    ans = input("AVISO: ¿Tienes autorización para realizar pruebas en estos hosts? (si/no): ").strip().lower()
    if ans in ("si", "s", "yes", "y"):
        logger.info("Autorización confirmada por el usuario.")
        return True
    logger.warning("Operación cancelada: autorización no confirmada.")
    return False


def osint_ipinfo_lookup(ip, timeout=5):
    """Consulta pasiva a ipinfo.io para obtener datos públicos sobre la IP.
    Retorna dict o None.
    """
    if SAFE_MODE:
        logger.info(f"[modo seguro] Simulando consulta ipinfo para {ip}")
        return None
    url = f"https://ipinfo.io/{ip}/json"
    try:
        logger.debug(f"Consultando ipinfo: {url}")
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.load(resp)
            logger.info(f"ipinfo datos para {ip}: {list(data.keys())}")
            return data
    except Exception as e:
        logger.debug(f"ipinfo lookup failed for {ip}: {e}")
        return None


def osint_shodan_lookup(ip, timeout=5):
    """Consulta a la API de Shodan si está configurada mediante la variable SHODAN_API_KEY.
    Retorna dict (respuesta) o None.
    """
    if SAFE_MODE:
        logger.info(f"[modo seguro] Simulando consulta Shodan para {ip}")
        return None
    key = None
    try:
        import os
        key = os.environ.get('SHODAN_API_KEY')
    except Exception:
        key = None
    if not key:
        logger.debug("SHODAN_API_KEY no configurada; omitiendo consulta Shodan.")
        return None
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
    try:
        logger.debug(f"Consultando Shodan: {url}")
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.load(resp)
            logger.info(f"Shodan datos para {ip}: keys={list(data.keys())}")
            return data
    except Exception as e:
        logger.debug(f"Shodan lookup failed for {ip}: {e}")
        return None

# ---------------- Interactive menu ----------------
def interactive_menu(state, show_intro=True):
    """Menú interactivo principal.

    Si show_intro es True muestra información previa (tabla ARP, resumen).
    Cuando se inicia con el flag --i se llamará con show_intro=False para
    mostrar únicamente el menú sin imprimir datos de ejecuciones anteriores.
    """
    if show_intro:
        arp_entries = arp_table_hosts()
        if arp_entries:
            logger.info("Hosts en tabla ARP local:")
            for entry in arp_entries:
                logger.info(f"{entry['ip']}\t{entry['mac']}")
        else:
            logger.info("No se detectaron hosts en la tabla ARP local.")
        logger.info("Se realizó un escaneo a red actual...")
    menu = """
=== NETWORK SCANNER - MENU INTERACTIVO ===
1) Descubrir hosts por subnet (ping sweep)
2) Añadir IPs manualmente (prompt)
3) Cargar hosts desde subnet automática detectada
4) Ejecutar escaneo TCP + banners
5) Ejecutar probes UDP
6) Ejecutar nmap (verificación)
7) Ejecutar fase RTSP (ffprobe)
8) Ejecutar heurística de detección de cámaras (auto)
9) Guardar resultados (CSV/JSON)
10) Mostrar resumen en pantalla
11) Ejecutar pipeline completo (discover -> tcp -> udp -> nmap -> rtsp -> heur)
q) Salir
-----------------------------------------------------------------
== Búsqueda de host ocultos y análisis detallado ==
a) Búsqueda intensiva de host
b) Análisis detallado de puertos abiertos
c) Búsqueda por MAC
d) OSINT pasivo (DNS/headers)
q) Salir
Elige opción: """
    while True:
        choice = input(menu).strip()
        if choice == "q":
            logger.info("Saliendo...")
            break
        elif choice == "1":
            if not ensure_authorized():
                continue
            subnet = input("Introduce subnet CIDR (ej: 192.168.1.0/24): ").strip()
            ips = discover_hosts_from_subnet(subnet)
            print(f"[=] Encontrados {len(ips)} hosts vivos.")
            state["ips"] = ips
        elif choice == "2":
            s = input("Introduce IPs separadas por coma: ").strip()
            ips = [ip.strip() for ip in s.split(",") if ip.strip()]
            state.setdefault("ips", [])
            state["ips"].extend(ips)
            state["ips"] = sorted(set(state["ips"]))
            logger.info(f"Hosts totales: {len(state['ips'])}")
        elif choice == "3":
            detected = detect_local_subnet()
            if not detected:
                logger.warning("No se pudo detectar subred automáticamente.")
            else:
                logger.info(f"Subred detectada: {detected}")
                ips = discover_hosts_from_subnet(detected)
                state["ips"] = ips
                logger.info(f"Hosts vivos: {len(ips)}")
        elif choice == "4":
            if not state.get("ips"):
                logger.warning("No hay IPs. Añade o descubre hosts primero.")
                continue
            if not ensure_authorized():
                continue
            tcp_ports_str = input(f"Puertos TCP a probar (coma-sep) [enter=default {DEFAULT_TCP_PORTS[:10]}...]: ").strip()
            tcp_ports = DEFAULT_TCP_PORTS if not tcp_ports_str else [int(x) for x in tcp_ports_str.split(",") if x.strip()]
            tcp_results = scan_tcp_and_banners(state["ips"], tcp_ports)
            # init state.results
            state.setdefault("results", {})
            for h, tcp in tcp_results.items():
                state["results"].setdefault(h, {"ip":h, "mac":None, "alive":True, "tcp":[], "udp":[], "rtsp":[], "camera_score":0, "camera_detected":False})
                state["results"][h]["tcp"] = tcp
            logger.info("Escaneo TCP OK.")
        elif choice == "5":
            if not state.get("ips"):
                logger.warning("No hay IPs. Añade o descubre hosts primero.")
                continue
            if not ensure_authorized():
                continue
            udp_ports_str = input(f"Puertos UDP a probar (coma-sep) [enter=default {DEFAULT_UDP_PORTS}]: ").strip()
            udp_ports = DEFAULT_UDP_PORTS if not udp_ports_str else [int(x) for x in udp_ports_str.split(",") if x.strip()]
            udp_results = scan_udp_hosts(state["ips"], udp_ports)
            state.setdefault("results", {})
            for h, udp in udp_results.items():
                state["results"].setdefault(h, {"ip":h, "mac":None, "alive":True, "tcp":[], "udp":[], "rtsp":[], "camera_score":0, "camera_detected":False})
                state["results"][h]["udp"] = udp
            logger.info("UDP probes OK.")
        elif choice == "6":
            if not state.get("ips"):
                logger.warning("No hay IPs. Añade o descubre hosts primero.")
                continue
            if not ensure_authorized():
                continue
            if not shutil.which("nmap"):
                logger.warning("nmap no está instalado o no está en PATH. Instálalo para usar esta opción.")
                continue
            port_spec = input("Especifica puerto(s) para nmap (ej: 80,554 o 1-65535): ").strip()
            if not port_spec:
                port_spec = ",".join(str(p) for p in DEFAULT_TCP_PORTS)
            nmap_res = run_nmap(state["ips"], port_spec)
            state.setdefault("results", {})
            for h, ports in nmap_res.items():
                state["results"].setdefault(h, {"ip":h, "mac":None, "alive":True, "tcp":[], "udp":[], "rtsp":[], "camera_score":0, "camera_detected":False})
                # integrate nmap ports
                for p in ports:
                    # append or update
                    state["results"][h]["tcp"].append({"port": p["port"], "open": (p["state"]=="open"), "banner": f"nmap:{p.get('service','')} {p.get('version','')}".strip(), "source":["nmap"]})
            logger.info("nmap verificacion OK.")
        elif choice == "7":
            if not state.get("results"):
                logger.warning("Ejecuta al menos el TCP scan (opción 4) o añade hosts.")
                continue
            if not ensure_authorized():
                continue
            hosts = list(state["results"].keys())
            rtsp_hits = rtsp_phase_over_hosts(hosts, {h: state["results"][h].get("tcp",[]) for h in hosts})
            for h, res in rtsp_hits.items():
                state["results"].setdefault(h, {"ip":h})
                state["results"][h]["rtsp"] = res
            logger.info("Fase RTSP OK.")
        elif choice == "8":
            if not state.get("results"):
                logger.warning("Ejecuta fases anteriores primero.")
                continue
            for h, info in state["results"].items():
                score, detected, reasons = heuristic_is_camera(info, [r for r in info.get("rtsp",[]) if r.get("ok")])
                info["camera_score"] = score
                info["camera_detected"] = detected
                info["camera_reasons"] = reasons
            logger.info("Heurística aplicada. Revisa el estado o guarda.")
        elif choice == "9":
            outcsv = input(f"CSV en [{OUT_CSV}]: ").strip() or OUT_CSV
            outjson = input(f"JSON en [{OUT_JSON}]: ").strip() or OUT_JSON
            save_results(state.get("results", {}), csvfile=outcsv, jsonfile=outjson)
            logger.info(f"Resultados guardados en {outcsv} y {outjson}")
        elif choice == "10":
            # mostrar resumen via logger
            res = state.get("results", {})
            for h, info in res.items():
                opens = [p["port"] for p in info.get("tcp",[]) if p.get("open")]
                rtsp_ok = [r for r in info.get("rtsp",[]) if r.get("ok")]
                logger.info(f"- {h} | alive={info.get('alive')} tcp_open={opens} rtsp_hits={len(rtsp_ok)} camera_detected={info.get('camera_detected')}")
        elif choice == "11":
            logger.info("Ejecutando pipeline completo...")
            # discover if not present
            if not ensure_authorized():
                continue
            if not state.get("ips"):
                subnet = detect_local_subnet()
                if not subnet:
                    print("[!] No se detectó subred local; añade ips o usa prompt.")
                    continue
                state["ips"] = discover_hosts_from_subnet(subnet)
            # tcp
            tcp_res = scan_tcp_and_banners(state["ips"], DEFAULT_TCP_PORTS)
            state["results"] = {}
            arp_entries = arp_table_hosts()
            mac_map = {e["ip"]: e.get("mac") for e in arp_entries}
            for h, tcp in tcp_res.items():
                state["results"][h] = {"ip":h, "mac": mac_map.get(h), "alive": True, "tcp": tcp, "udp": [], "rtsp": [], "camera_score":0, "camera_detected":False}
            # udp
            udp_res = scan_udp_hosts(state["ips"], DEFAULT_UDP_PORTS)
            for h, udp in udp_res.items():
                state["results"].setdefault(h, {"ip":h})
                state["results"][h]["udp"] = udp
            # nmap
            if shutil.which("nmap"):
                print("[*] Ejecutando nmap (verificación)...")
                port_spec = ",".join(str(p) for p in DEFAULT_TCP_PORTS)
                nmap_out = run_nmap(list(state["results"].keys()), port_spec)
                for h, ports in nmap_out.items():
                    for p in ports:
                        state["results"][h]["tcp"].append({"port": p["port"], "open": (p["state"]=="open"), "banner": f"nmap:{p.get('service','')} {p.get('version','')}", "source":["nmap"]})
            # rtsp
            hosts = list(state["results"].keys())
            rtsp_out = rtsp_phase_over_hosts(hosts, {h: state["results"][h].get("tcp",[]) for h in hosts})
            for h, arr in rtsp_out.items():
                state["results"][h]["rtsp"] = arr
            # heuristics
            for h, info in state["results"].items():
                score, detected, reasons = heuristic_is_camera(info, [r for r in info.get("rtsp",[]) if r.get("ok")])
                info["camera_score"] = score
                info["camera_detected"] = detected
                info["camera_reasons"] = reasons
            print("[=] Pipeline completo ejecutado.")
        elif choice == "a":
            # Búsqueda intensiva de host: realiza un escaneo TCP más agresivo sobre
            # un objetivo concreto (subnet o lista de IPs). Se solicita confirmación.
            if not ensure_authorized():
                continue
            target = input("Introduce subnet CIDR o lista de IPs (coma-sep) para búsqueda intensiva: ").strip()
            if not target:
                logger.warning("Objetivo no especificado.")
                continue
            # Determinar lista de hosts
            if "/" in target:
                try:
                    hosts = discover_hosts_from_subnet(target)
                except Exception as e:
                    logger.exception(f"Error al procesar subnet: {e}")
                    continue
            else:
                hosts = [ip.strip() for ip in target.split(",") if ip.strip()]
            if not hosts:
                logger.warning("No se encontraron hosts para escanear.")
                continue
            ports_str = input("Puertos TCP adicionales (coma-sep) [enter=usar por defecto]: ").strip()
            ports = DEFAULT_TCP_PORTS if not ports_str else [int(x) for x in ports_str.split(",") if x.strip()]
            logger.info(f"Ejecutando escaneo intensivo en {len(hosts)} hosts...")
            tcp_results = scan_tcp_and_banners(hosts, ports, threads=100)
            # Integrar en estado
            state.setdefault("results", {})
            arp_entries = arp_table_hosts()
            mac_map = {e["ip"]: e.get("mac") for e in arp_entries}
            for h, tcp in tcp_results.items():
                state["results"].setdefault(h, {"ip":h, "mac": mac_map.get(h), "alive": True, "tcp": [], "udp": [], "rtsp": [], "camera_score":0, "camera_detected":False})
                state["results"][h]["tcp"] = tcp
            logger.info("Búsqueda intensiva completada.")
        elif choice == "b":
            # Análisis detallado de puertos abiertos: muestra información recolectada
            # para un host y permite ejecutar nmap como verificación (si está disponible).
            if not state.get("results"):
                logger.warning("No hay resultados. Ejecuta un escaneo primero.")
                continue
            host = input("Introduce el host (IP) para análisis detallado: ").strip()
            if host not in state.get("results", {}):
                logger.warning("Host no encontrado en los resultados.")
                continue
            info = state["results"][host]
            logger.info(json.dumps(info, indent=2, ensure_ascii=False))
            if shutil.which("nmap"):
                if ensure_authorized():
                    do_nmap = input("¿Ejecutar nmap de verificación en este host? (si/no): ").strip().lower()
                    if do_nmap in ("si","s","yes","y"):
                        port_spec = input("Puertos para nmap (ej: 1-65535) [enter=por defecto]: ").strip()
                        if not port_spec:
                            port_spec = ",".join(str(p) for p in DEFAULT_TCP_PORTS)
                        nmap_res = run_nmap([host], port_spec)
                        if nmap_res.get(host):
                            for p in nmap_res[host]:
                                info.setdefault("tcp", []).append({"port": p["port"], "open": (p["state"]=="open"), "banner": f"nmap:{p.get('service','')} {p.get('version','')}", "source":["nmap"]})
                            logger.info("nmap integrado en resultados del host.")
            else:
                logger.warning("nmap no disponible en PATH.")
        elif choice == "c":
            # Buscar hosts por MAC en los resultados/tabla ARP
            mac_q = input("Introduce parte o prefijo de MAC a buscar (ej: 00:1A:): ").strip().lower()
            if not mac_q:
                print("[!] Debes especificar una cadena MAC.")
                continue
            matches = []
            # buscar en tabla ARP y en resultados
            arp_entries = arp_table_hosts()
            for e in arp_entries:
                if mac_q in (e.get("mac") or "").lower():
                    matches.append({"ip": e.get("ip"), "mac": e.get("mac"), "source": "arp"})
            for h, info in state.get("results", {}).items():
                mac = (info.get("mac") or "").lower()
                if mac_q in mac:
                    matches.append({"ip": h, "mac": info.get("mac"), "source": "results"})
            if not matches:
                logger.info("No se encontraron coincidencias para la MAC proporcionada.")
            else:
                for m in matches:
                    logger.info(f"- {m['ip']} \t {m['mac']} \t ({m['source']})")
        elif choice == "d":
            # OSINT pasivo: resolución DNS reversa y cabeceras HTTP(S) simples
            if not state.get("ips"):
                logger.warning("No hay IPs. Añade o descubre hosts primero.")
                continue
            hosts = state.get("ips")
            logger.info("Iniciando OSINT pasivo sobre hosts listados")
            for h in hosts:
                logger.info(f"OSINT pasivo para {h}:")
                if SAFE_MODE:
                    logger.info(f"[modo seguro] Simulando OSINT pasivo para {h}")
                    continue
                # Reverse DNS
                try:
                    rdns = socket.gethostbyaddr(h)[0]
                    logger.info(f"DNS reverso: {rdns}")
                except Exception:
                    logger.debug("DNS reverso no disponible")
                # HTTP HEAD
                for scheme in ("http", "https"):
                    url = f"{scheme}://{h}/"
                    try:
                        req = urllib.request.Request(url, method='HEAD')
                        with urllib.request.urlopen(req, timeout=3) as resp:
                            headers = dict(resp.getheaders())
                            logger.info(f"{scheme.upper()} headers: {list(headers.keys())}")
                    except urllib.error.HTTPError as e:
                        logger.info(f"{scheme.upper()} HTTPError: {e.code}")
                    except Exception:
                        logger.debug(f"{scheme.upper()} no disponible o timeout")
        else:
            logger.warning("Opción no válida.")

# ------------------ Main CLI runner ------------------
def main():
    parser = argparse.ArgumentParser(description="Network Super Scanner (interactivo + rtsp + heuristica).")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--subnet", help="CIDR a escanear (ex: 192.168.1.0/24). Si se omite, auto-detectara /24.")
    group.add_argument("--ips", help="Separadas por coma")
    parser.add_argument("--ip", action="store_true", help="Prompt para IPs.")
    parser.add_argument("--i", action="store_true", help="Carga Menu CLI (Interfaz consola)")
    parser.add_argument("--modo-seguro", action="store_true", help="Modo seguro: simula las pruebas y no realiza tráfico de red (dry-run).")
    parser.add_argument("--confirm", action="store_true", help="Confirmación explícita de autorización para escanear (omite prompt interactivo de autorización).")
    parser.add_argument("--no-udp", action="store_true", help="Salta UDP probes.")
    parser.add_argument("--no-nmap", action="store_true", help="Salta nmap.")
    parser.add_argument("--ffprobe-timeout", type=float, default=5.0, help="Cuanto tiempo (s) para intentos de ffprobe.")
    parser.add_argument("--out-csv", default=OUT_CSV)
    parser.add_argument("--out-json", default=OUT_JSON)
    args = parser.parse_args()

    state = {}
    # establecer modo seguro global según argumento
    global SAFE_MODE
    SAFE_MODE = bool(args.modo_seguro)
    # Si se solicita modo interactivo, arrancar únicamente la CLI sin
    # realizar detecciones o escaneos automáticos previos.
    if args.i:
        state["ips"] = []
        # no mostrar información previa al iniciar en modo interactivo
        interactive_menu(state, show_intro=False)
        logger.info("Sesion interactiva finalizada (modo --i).")
        return
    # build initial IP list
    ips = []
    if args.ip:
        s = input("Introduce IPs (coma-sep): ").strip()
        ips = [ip.strip() for ip in s.split(",") if ip.strip()]
    elif args.ips:
        ips = [ip.strip() for ip in args.ips.split(",") if ip.strip()]
    else:
        subnet = args.subnet or detect_local_subnet()
        if not subnet:
            print("[!] No pude detectar subred local. Usa --subnet, --ips o --ip.")
            # still allow interactive
            if args.i:
                state["ips"] = []
                interactive_menu(state)
                logger.info("Sesion interactiva finalizada (subnet no detectada)")
                return
            sys.exit(1)
        print(f"[*] Subnet: {subnet}")
        ips = discover_hosts_from_subnet(subnet)

    state["ips"] = ips
    print(f"[*] Candidato para Host inicial: {len(ips)}")

    # Non-interactive pipeline: tcp -> udp -> nmap (optional) -> rtsp -> heuristics
    # antes de ejecutar pipeline no interactivo, pedir autorización si no se confirmó
    if not args.confirm and not SAFE_MODE:
        print("\nAVISO LEGAL: Debes tener autorización para escanear la red/hosts objetivo.\n")
        ok = input("¿Confirmas que tienes autorización para proceder? (si/no): ").strip().lower()
        if ok not in ("si","s","yes","y"):
            print("[!] No se confirmó autorización. Abortando ejecución.")
            sys.exit(1)

    results = {}
    arp_entries = arp_table_hosts()
    mac_map = {e["ip"]: e.get("mac") for e in arp_entries}

    tcp_map = scan_tcp_and_banners(state["ips"], DEFAULT_TCP_PORTS)
    for h, tcp in tcp_map.items():
        results[h] = {"ip":h, "mac": mac_map.get(h), "alive": True, "tcp": tcp, "udp": [], "rtsp": [], "camera_score":0, "camera_detected":False}

    if not args.no_udp:
        udp_map = scan_udp_hosts(state["ips"], DEFAULT_UDP_PORTS)
        for h, udp in udp_map.items():
            results[h]["udp"] = udp

    # nmap optional
    if not args.no_nmap and shutil.which("nmap"):
        print("[*] Verificando resultados con nmap...")
        port_spec = ",".join(str(p) for p in DEFAULT_TCP_PORTS)
        nmap_out = run_nmap(list(results.keys()), port_spec)
        for h, ports in nmap_out.items():
            for p in ports:
                results[h]["tcp"].append({"port": p["port"], "open": (p["state"]=="open"), "banner": f"nmap:{p.get('service','')} {p.get('version','')}", "source":["nmap"]})

    # RTSP phase
    hosts = list(results.keys())
    rtsp_out = rtsp_phase_over_hosts(hosts, {h: results[h].get("tcp",[]) for h in hosts}, timeout=args.ffprobe_timeout)
    for h, arr in rtsp_out.items():
        results[h]["rtsp"] = arr

    # heuristics
    for h, info in results.items():
        score, detected, reasons = heuristic_is_camera(info, [r for r in info.get("rtsp",[]) if r.get("ok")])
        info["camera_score"] = score
        info["camera_detected"] = detected
        info["camera_reasons"] = reasons

    save_results(results, csvfile=args.out_csv, jsonfile=args.out_json)
    logger.info("OK. Revisa informes y examina host con camera_detected=True con cuidado.")

if __name__ == "__main__":
    main()


