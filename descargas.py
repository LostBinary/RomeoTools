#!/usr/bin/env python3
"""
Bandwidth Monitor — velocidad global, procesos con red activa y hex dump de paquetes grandes
Requiere: pip install psutil scapy
Uso:      sudo python bandwidth_monitor.py [interfaz]
          sudo python bandwidth_monitor.py          # todas las interfaces
          sudo python bandwidth_monitor.py eth0     # solo eth0

NOTA: se necesita sudo/root para capturar paquetes con scapy.
      Sin privilegios la sección hex queda desactivada automáticamente.
"""

import sys
import time
import os
import threading
from typing import Optional

try:
    import psutil
except ImportError:
    sys.exit("❌  Instala psutil:  pip install psutil")

SCAPY_OK = False
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, conf
    conf.verb = 0
    SCAPY_OK = True
except Exception:
    pass

# ── configuración ─────────────────────────────────────────────────────────────
INTERVAL       = 1.0    # segundos entre refresco
BAR_WIDTH      =32     # anchura de la barra
MAX_MBPS       = 70.0  # escala máxima de la barra
TOP_PROCS      = 6      # procesos a mostrar
HEX_PACKETS    = 2      # paquetes grandes a volcar
HEX_BYTES_SHOW = 32     # bytes de payload a mostrar
MIN_PKT_SIZE   = 1024    # tamaño mínimo para "paquete grande"

# ── colores ANSI ──────────────────────────────────────────────────────────────
R    = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[2m"
CYAN = "\033[96m"
GRN  = "\033[92m"
AMB  = "\033[93m"
RED  = "\033[91m"
BLUE = "\033[94m"
MGN  = "\033[95m"
WHT  = "\033[97m"

USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def c(code: str, text: str) -> str:
    return f"{code}{text}{R}" if USE_COLOR else text

# ── formato ───────────────────────────────────────────────────────────────────
def speed_col(mbps: float) -> str:
    if mbps >= MAX_MBPS * 0.75: return RED
    if mbps >= MAX_MBPS * 0.35: return AMB
    return GRN

def bar(mbps: float) -> str:
    n = int(min(mbps / MAX_MBPS, 1.0) * BAR_WIDTH)
    inner = c(speed_col(mbps), "█" * n) + c(DIM, "░" * (BAR_WIDTH - n))
    return f"[{inner}]"

def fmt_speed(mbps: float) -> str:
    return c(speed_col(mbps), f"{mbps:7.3f} MBps")

def fmt_bytes(b: int) -> str:
    if b < 1024:      return f"{b} B"
    if b < 1024**2:   return f"{b/1024:.1f} KB"
    if b < 1024**3:   return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"

def hex_dump(data: bytes, limit: int = HEX_BYTES_SHOW) -> list:
    chunk = data[:limit]
    out = []
    for i in range(0, len(chunk), 16):
        row  = chunk[i:i+16]
        hex_ = " ".join(f"{b:02x}" for b in row)
        asc  = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"    {i:04x}  {hex_:<48}  {asc}")
    if len(data) > limit:
        out.append(f"    ... ({len(data)-limit} bytes más)")
    return out

# ── captura de paquetes en background ─────────────────────────────────────────
class PacketCapture:
    def __init__(self, iface: Optional[str]):
        self.iface  = iface
        self._lock  = threading.Lock()
        self._pkts  = []   # (size, payload_bytes, info_str)
        self._stop  = threading.Event()

    def start(self):
        if not SCAPY_OK:
            return
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        kw = dict(prn=self._handle, store=False,
                  stop_filter=lambda _: self._stop.is_set())
        if self.iface:
            kw["iface"] = self.iface
        try:
            sniff(**kw)
        except Exception:
            pass

    def _handle(self, pkt):
        if not pkt.haslayer(IP):
            return
        size = len(pkt)
        if size < MIN_PKT_SIZE:
            return
        proto   = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "IP"
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else bytes(pkt[IP])
        src, dst = pkt[IP].src, pkt[IP].dst
        info = f"{proto}  {src} → {dst}  ({size} B)"
        with self._lock:
            self._pkts.append((size, payload, info))
            if len(self._pkts) > 60:
                self._pkts.sort(key=lambda x: x[0], reverse=True)
                self._pkts = self._pkts[:60]

    def flush(self) -> list:
        with self._lock:
            top = sorted(self._pkts, key=lambda x: x[0], reverse=True)[:HEX_PACKETS]
            self._pkts.clear()
            return top

    def stop(self):
        self._stop.set()

# ── contadores globales ───────────────────────────────────────────────────────
def get_counters(iface: Optional[str]) -> tuple:
    stats = psutil.net_io_counters(pernic=bool(iface))
    if iface:
        if iface not in stats:
            print(f"\n❌  Interfaz '{iface}' no encontrada.")
            print("Disponibles:", ", ".join(psutil.net_io_counters(pernic=True).keys()))
            sys.exit(1)
        s = stats[iface]
    else:
        s = stats
    return s.bytes_recv, s.bytes_sent

# ── procesos con conexiones activas ───────────────────────────────────────────
def active_connections() -> list:
    """Devuelve lista de (nombre, pid, local, remoto) para conexiones establecidas."""
    seen = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for cn in proc.connections(kind="inet"):
                if cn.status in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
                    if proc.pid not in seen:
                        la = f"{cn.laddr.ip}:{cn.laddr.port}" if cn.laddr else "-"
                        ra = f"{cn.raddr.ip}:{cn.raddr.port}" if cn.raddr else "-"
                        seen[proc.pid] = (proc.info["name"] or "?", proc.pid, la, ra)
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return list(seen.values())

# ── renderizado ───────────────────────────────────────────────────────────────
_prev_lines = 0

def clear_prev():
    global _prev_lines
    if USE_COLOR and _prev_lines:
        sys.stdout.write(f"\033[{_prev_lines}A\033[J")
        sys.stdout.flush()

def render(dl: float, ul: float, total_dl: int, total_ul: int,
           label: str, elapsed: float, packets: list, first: bool):
    global _prev_lines

    SEP = c(DIM, "  " + "─" * 64)
    out = []

    # ── cabecera ──────────────────────────────────────────────────────────────
    out += [
        "",
        c(BOLD + CYAN, f"  ▶  Bandwidth Monitor  —  {label}"),
        c(DIM,         f"     t={int(elapsed)}s  │  intervalo={INTERVAL}s  │  escala={MAX_MBPS} MBps"),
        "",
    ]

    # ── velocidad ─────────────────────────────────────────────────────────────
    out += [
        c(BOLD + WHT, "  VELOCIDAD"),
        SEP,
        f"  {c(BLUE, '↓ Descarga')}  {bar(dl)}  {fmt_speed(dl)}",
        f"  {c(AMB,  '↑ Subida  ')}  {bar(ul)}  {fmt_speed(ul)}",
        c(DIM, f"  Total recibido: {fmt_bytes(total_dl):>12}    Total enviado: {fmt_bytes(total_ul):>12}"),
        "",
    ]

    # ── procesos ──────────────────────────────────────────────────────────────
    out += [c(BOLD + WHT, "  PROCESOS CON RED ACTIVA"), SEP]

    conns = active_connections()
    if conns:
        out.append(
            f"  {c(DIM,'PID'):>10}  {c(DIM,'PROCESO'):<24}  "
            f"{c(DIM,'LOCAL'):<22}  {c(DIM,'REMOTO')}"
        )
        for name, pid, la, ra in conns[:TOP_PROCS]:
            pid_s  = c(CYAN, str(pid))
            name_s = c(WHT,  name[:22])
            la_s   = c(DIM,  la[:22])
            ra_s   = c(GRN,  ra[:30])
            out.append(f"  {pid_s:>10}  {name_s:<24}  {la_s:<22}  {ra_s}")
        if len(conns) > TOP_PROCS:
            out.append(c(DIM, f"  … y {len(conns)-TOP_PROCS} procesos más"))
    else:
        out.append(c(DIM, "  (sin conexiones establecidas)"))
    out.append("")

    # ── hex dump paquetes grandes ─────────────────────────────────────────────
    out += [c(BOLD + WHT, f"  PAQUETES GRANDES  (≥{MIN_PKT_SIZE} B, hex dump)"), SEP]

    if not SCAPY_OK:
        out.append(c(AMB, "  ⚠  scapy no instalado  →  pip install scapy  (requiere sudo)"))
    elif not packets:
        out.append(c(DIM, f"  (ningún paquete ≥ {MIN_PKT_SIZE} B capturado en este intervalo)"))
    else:
        for idx, (size, payload, info) in enumerate(packets, 1):
            out.append(f"  {c(MGN, f'#{idx}')}  {c(WHT, info)}")
            for hl in hex_dump(payload):
                out.append(c(DIM, hl))
            if idx < len(packets):
                out.append("")

    out.append("")

    # ── escribir ──────────────────────────────────────────────────────────────
    if not first:
        clear_prev()

    text = "\n".join(out)
    print(text, end="", flush=True)
    _prev_lines = text.count("\n") + 1

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    label = iface if iface else "todas las interfaces"
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    print(c(BOLD, "\n  Iniciando monitor…"))
    if not SCAPY_OK:
        print(c(AMB, "  ⚠  scapy no encontrado — hex dump desactivado"))
        print(c(DIM, "     Instala con:  pip install scapy"))
    elif not is_root:
        print(c(AMB, "  ⚠  sin root — la captura de paquetes puede fallar"))
        print(c(DIM, "     Ejecuta con:  sudo python bandwidth_monitor.py"))
    print(c(DIM, "  Ctrl+C para salir\n"))
    time.sleep(0.3)

    cap = PacketCapture(iface)
    cap.start()

    prev_recv, prev_sent = get_counters(iface)
    start = time.monotonic()
    first = True

    try:
        while True:
            time.sleep(INTERVAL)
            now_recv, now_sent = get_counters(iface)
            dl = (now_recv - prev_recv) / INTERVAL / 1024**2
            ul = (now_sent - prev_sent) / INTERVAL / 1024**2

            render(
                dl=dl, ul=ul,
                total_dl=now_recv, total_ul=now_sent,
                label=label,
                elapsed=time.monotonic() - start,
                packets=cap.flush(),
                first=first,
            )
            prev_recv, prev_sent = now_recv, now_sent
            first = False

    except KeyboardInterrupt:
        cap.stop()
        print(c(DIM, "\n\n  Monitor detenido.\n"))

if __name__ == "__main__":
    main()