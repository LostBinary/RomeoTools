#!/usr/bin/env python3
"""
Bandwidth Monitor — muestra velocidad de descarga/subida en tiempo real (MBps)
Requiere: pip install psutil
Uso:      python bandwidth_monitor.py [interfaz]
          python bandwidth_monitor.py          # monitoriza todas las interfaces
          python bandwidth_monitor.py eth0     # solo eth0
"""

import sys
import time
import os
import psutil

INTERVAL = 4.0          # segundos entre muestras
BAR_WIDTH = 32          # ancho de la barra de progreso
MAX_MBPS  = 2000.0       # escala máxima de la barra (ajústala a tu conexión)

# ── colores ANSI ──────────────────────────────────────────────────────────────
R  = "\033[0m"           # reset
BOLD  = "\033[1m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
AMBER = "\033[93m"
RED   = "\033[91m"
DIM   = "\033[2m"
BLUE  = "\033[94m"

def supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = supports_color()

def c(code: str, text: str) -> str:
    return f"{code}{text}{R}" if USE_COLOR else text

def speed_color(mbps: float) -> str:
    if mbps >= MAX_MBPS * 0.75:
        return RED
    if mbps >= MAX_MBPS * 0.35:
        return AMBER
    return GREEN

def bar(mbps: float) -> str:
    filled = int(min(mbps / MAX_MBPS, 1.0) * BAR_WIDTH)
    empty  = BAR_WIDTH - filled
    col    = speed_color(mbps)
    inner  = c(col, "█" * filled) + c(DIM, "░" * empty)
    return f"[{inner}]"

def fmt_speed(mbps: float) -> str:
    col = speed_color(mbps)
    return c(col, f"{mbps:7.3f} MBps")

def fmt_total(bytes_: int) -> str:
    if bytes_ < 1024:
        return f"{bytes_} B"
    if bytes_ < 1024 ** 2:
        return f"{bytes_/1024:.1f} KB"
    if bytes_ < 1024 ** 3:
        return f"{bytes_/1024**2:.1f} MB"
    return f"{bytes_/1024**3:.2f} GB"

def get_counters(iface: str | None):
    stats = psutil.net_io_counters(pernic=bool(iface))
    if iface:
        if iface not in stats:
            print(f"\n❌  Interfaz '{iface}' no encontrada.")
            print("Interfaces disponibles:", ", ".join(psutil.net_io_counters(pernic=True).keys()))
            sys.exit(1)
        s = stats[iface]
    else:
        s = stats  # totales globales
    return s.bytes_recv, s.bytes_sent

def clear_lines(n: int):
    if USE_COLOR:
        for _ in range(n):
            sys.stdout.write("\033[1A\033[2K")
    sys.stdout.flush()

def render(dl: float, ul: float,
           total_dl: int, total_ul: int,
           iface_label: str, elapsed: float,
           first: bool):

    lines = [
        "",
        c(BOLD + CYAN, f"  ▶  Monitor de ancho de banda  —  {iface_label}"),
        c(DIM, f"     Intervalo: {INTERVAL}s  |  Escala barra: {MAX_MBPS} MBps  |  Tiempo: {int(elapsed)}s"),
        "",
        f"  {c(BLUE, '↓ Descarga')}  {bar(dl)}  {fmt_speed(dl)}",
        f"  {c(AMBER,'↑ Subida  ')}  {bar(ul)}  {fmt_speed(ul)}",
        "",
        c(DIM, f"  Total recibido: {fmt_total(total_dl):>12}    Total enviado: {fmt_total(total_ul):>12}"),
        "",
    ]

    if not first:
        clear_lines(len(lines))

    print("\n".join(lines))

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    label = iface if iface else "todas las interfaces"

    print(c(BOLD, "\n  Iniciando monitor… (Ctrl+C para salir)\n"))
    time.sleep(0.2)

    prev_recv, prev_sent = get_counters(iface)
    start = time.monotonic()
    first = True

    try:
        while True:
            time.sleep(INTERVAL)
            now_recv, now_sent = get_counters(iface)

            dl_bps = (now_recv - prev_recv) / INTERVAL
            ul_bps = (now_sent - prev_sent) / INTERVAL

            dl_mbps = dl_bps / (1024 ** 2)
            ul_mbps = ul_bps / (1024 ** 2)

            elapsed = time.monotonic() - start
            render(dl_mbps, ul_mbps, now_recv, now_sent, label, elapsed, first)

            prev_recv, prev_sent = now_recv, now_sent
            first = False

    except KeyboardInterrupt:
        print(c(DIM, "\n  Monitor detenido.\n"))

if __name__ == "__main__":
    main()