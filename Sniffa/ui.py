"""
Run this file to start the IDS:  sudo python ui.py

Layout (refreshes every second):
┌─────────────────────────────── header ─────────────────────────────────┐
│  title · uptime · pkt/s · total packets · ML status                    │
├──────────────┬──────────────┬──────────────┬──────────────────────────-┤
│  protocols   │  top talkers │  countries   │  services                 │
├──────────────┴──────────────┴──────────────┴───────────────────────────┤
│  live packet log (left)                  │  alerts (right)             │
└──────────────────────────────────────────┴─────────────────────────────┘
"""

import threading
import time
from datetime import datetime, timedelta

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from rich.align import Align

import stats
import sniffer

# ── colour palette ─────────────────────────────────────────────────────────
C_TITLE  = "bold cyan"
C_GOOD   = "green"
C_WARN   = "yellow"
C_ALERT  = "bold red"
C_DIM    = "dim white"
C_HEAD   = "bold white"
C_ACCENT = "bright_cyan"

REFRESH_RATE  = 1.0
TOP_TALKERS   = 8
TOP_COUNTRIES = 8
TOP_SERVICES  = 8
MAX_ALERTS    = 16
MAX_LOG_ROWS  = 16

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "OTHER"}

console = Console()

# ============================================================
# PANEL BUILDERS
# ============================================================

def _uptime() -> str:
    delta = int(time.time() - stats.start_time)
    return str(timedelta(seconds=delta))


def build_header() -> Panel:
    pps   = stats.packets_per_second()
    total = stats.total_packets
    drops = stats.dropped_packets
    ml    = "[green]ON[/]" if stats.ml_enabled else "[yellow]OFF[/]"
    drop_str = (f"  [red]dropped {drops:,}[/]" if drops else "")

    line = (
        f"[{C_TITLE}]  ▶  SNIFFA IDS[/]   "
        f"uptime [cyan]{_uptime()}[/]   "
        f"packets [white]{total:,}[/]{drop_str}   "
        f"[{C_ACCENT}]{pps:,} pkt/s[/]   "
        f"ML [{C_DIM}]{ml}[/]   "
        f"[{C_DIM}]{datetime.now().strftime('%H:%M:%S')}[/]"
    )
    return Panel(Align.center(line), style="bold", box=box.HORIZONTALS)


def build_proto_table() -> Panel:
    t = Table(box=box.SIMPLE, show_header=True, header_style=C_HEAD,
              expand=True, padding=(0, 1))
    t.add_column("Proto", style=C_ACCENT, width=6)
    t.add_column("Packets", justify="right")
    t.add_column("Share",   justify="right", style=C_DIM)

    total = max(stats.total_packets, 1)
    for num, name in PROTO_NAMES.items():
        count = stats.proto_counts.get(num, 0)
        pct   = count / total * 100
        bar   = "█" * int(pct / 5)
        t.add_row(name, f"{count:,}", f"{pct:4.1f}% {bar}")

    return Panel(t, title="[bold]Protocols[/]", box=box.ROUNDED,
                 border_style="cyan", padding=(0, 1))


def build_top_talkers() -> Panel:
    t = Table(box=box.SIMPLE, show_header=True, header_style=C_HEAD,
              expand=True, padding=(0, 1))
    t.add_column("#",         width=3,  style=C_DIM)
    t.add_column("Source IP", style=C_ACCENT)
    t.add_column("Packets",   justify="right")

    sorted_talkers = sorted(
        stats.top_talkers.items(), key=lambda x: x[1], reverse=True
    )[:TOP_TALKERS]

    for rank, (ip, count) in enumerate(sorted_talkers, 1):
        style = C_ALERT if count > 10_000 else ""
        t.add_row(str(rank), ip, f"{count:,}", style=style)

    return Panel(t, title="[bold]Top Talkers[/]", box=box.ROUNDED,
                 border_style="cyan", padding=(0, 1))


def build_country_table() -> Panel:
    t = Table(box=box.SIMPLE, show_header=True, header_style=C_HEAD,
              expand=True, padding=(0, 1))
    t.add_column("CC",      width=7, style=C_ACCENT)
    t.add_column("Packets", justify="right")

    for cc, count in sorted(
        stats.country_counts.items(), key=lambda x: x[1], reverse=True
    )[:TOP_COUNTRIES]:
        t.add_row(cc, f"{count:,}")

    return Panel(t, title="[bold]Countries[/]", box=box.ROUNDED,
                 border_style="blue", padding=(0, 1))


def build_service_table() -> Panel:
    t = Table(box=box.SIMPLE, show_header=True, header_style=C_HEAD,
              expand=True, padding=(0, 1))
    t.add_column("Service", style=C_ACCENT)
    t.add_column("Packets", justify="right")

    for svc, count in sorted(
        stats.service_counts.items(), key=lambda x: x[1], reverse=True
    )[:TOP_SERVICES]:
        t.add_row(svc, f"{count:,}")

    return Panel(t, title="[bold]Services[/]", box=box.ROUNDED,
                 border_style="blue", padding=(0, 1))


def build_live_log() -> Panel:
    t = Table(box=box.SIMPLE, show_header=True, header_style=C_HEAD,
              expand=True, padding=(0, 1))
    t.add_column("Time",    width=8,  style=C_DIM)
    t.add_column("Proto",   width=5,  style=C_ACCENT)
    t.add_column("Src IP",  width=15, style=C_ACCENT)
    t.add_column("Dst IP",  width=15)
    t.add_column("Sport",   width=6,  justify="right", style=C_DIM)
    t.add_column("Dport",   width=6,  justify="right", style=C_DIM)
    t.add_column("CC",      width=4,  style=C_DIM)
    t.add_column("Service", style=C_DIM)
    t.add_column("Len",     width=6,  justify="right", style=C_DIM)

    with stats.log_lock:
        rows = list(stats.recent_packets)[:MAX_LOG_ROWS]

    for p in rows:
        try:
            ts_short = p["ts"][11:19]
        except Exception:
            ts_short = p["ts"]

        proto_name = PROTO_NAMES.get(p["proto"], "???")
        t.add_row(
            ts_short,
            proto_name,
            p["src_ip"],
            p["dst_ip"],
            str(p["src_port"]),
            str(p["dst_port"]),
            p["country"],
            p["service"],
            str(p["pkt_len"]),
        )

    return Panel(t, title="[bold]Live Log[/]", box=box.ROUNDED,
                 border_style="green", padding=(0, 1))


def build_alerts_panel() -> Panel:
    t = Table(box=box.SIMPLE, show_header=True, header_style=C_HEAD,
              expand=True, padding=(0, 1))
    t.add_column("Time",   width=8,  style=C_DIM)
    t.add_column("Source", width=15, style=C_ACCENT)
    t.add_column("Type",   width=18, style=C_WARN)
    t.add_column("Val",    width=6,  justify="right")
    t.add_column("Org / Service", style=C_DIM)

    with stats.alerts_lock:
        rows = list(stats.recent_alerts)[:MAX_ALERTS]

    for a in rows:
        try:
            ts_short = a["ts"][11:19]
        except Exception:
            ts_short = a["ts"]

        alert_style = (C_ALERT if "FLOOD" in a["type"] or "SCAN" in a["type"]
                       else C_WARN)
        t.add_row(
            ts_short,
            a["src_ip"],
            Text(a["type"], style=alert_style),
            str(a["value"]),
            f"{a['org']}  {a['service']}",
        )

    total_str = f"[{C_DIM}]total {stats.total_alerts}[/]"
    return Panel(t, title=f"[bold red]⚠  Alerts[/]  {total_str}",
                 box=box.ROUNDED, border_style="red", padding=(0, 1))


# ============================================================
# LAYOUT ASSEMBLY
# ============================================================

def build_layout() -> Layout:
    root = Layout()

    root.split_column(
        Layout(name="header", size=3),
        Layout(name="top",    ratio=2),
        Layout(name="bottom", ratio=3),
    )

    root["top"].split_row(
        Layout(name="proto"),
        Layout(name="talkers"),
        Layout(name="countries"),
        Layout(name="services"),
    )

    root["bottom"].split_row(
        Layout(name="live_log", ratio=3),
        Layout(name="alerts",   ratio=2),
    )

    return root


def refresh_layout(layout: Layout) -> None:
    layout["header"].update(build_header())
    layout["proto"].update(build_proto_table())
    layout["talkers"].update(build_top_talkers())
    layout["countries"].update(build_country_table())
    layout["services"].update(build_service_table())
    layout["live_log"].update(build_live_log())
    layout["alerts"].update(build_alerts_panel())


# ============================================================
# ENTRY POINT
# ============================================================

def main() -> None:
    console.print(
        "\n[bold cyan]Sniffa IDS[/]  starting capture "
        "[dim](Ctrl+C to quit)[/]\n"
    )

    sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
    sniffer_thread.start()

    layout = build_layout()

    with Live(layout, console=console,
              refresh_per_second=int(1 / REFRESH_RATE),
              screen=True) as live:
        try:
            while True:
                refresh_layout(layout)
                time.sleep(REFRESH_RATE)
        except KeyboardInterrupt:
            pass

    console.print(
        "\n[bold cyan]Sniffa[/] stopped. Logs saved to "
        f"[green]{sniffer.CSV_FILE}[/] and "
        f"[green]{sniffer.ALERT_FILE}[/]\n"
    )


if __name__ == "__main__":
    main()
