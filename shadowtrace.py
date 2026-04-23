#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import threading
import argparse
import webbrowser
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
from scapy.all import sniff, IP, TCP, UDP
from rich.console import Console
from rich.panel import Panel
import websockets

__author__ = "Akrem Chikhaoui"
__version__ = "1.0"

console = Console()
ip_cache = {}
executor = ThreadPoolExecutor(max_workers=10)
print_lock = threading.Lock()

connected_clients = set()

parser = argparse.ArgumentParser(description="ShadowTrace - Passive OSINT with Live Dashboard")
parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff on")
parser.add_argument("--no-browser", action="store_true", help="Disable auto-opening dashboard")
parser.add_argument("--log", "-l", type=str, help="Export results to JSON file")
parser.add_argument("--target", "-t", type=str, help="Filter by target IP")
parser.add_argument("--port", "-p", type=int, default=8765, help="WebSocket server port (default: 8765)")
args = parser.parse_args()

def get_flag(country_code):
    if not country_code:
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in country_code.upper())

def get_detailed_os(packet):
    if not packet.haslayer(TCP):
        return "UDP Traffic (No OS Fingerprint)"
    ttl = packet[IP].ttl
    window = packet[TCP].window
    if ttl <= 64:
        if window in [5840, 5720]:
            return "Linux Kernel (Server/Ubuntu)"
        if window == 65535:
            return "macOS / iOS Device"
        return "Android/Linux Mobile"
    elif ttl <= 128:
        if window == 8192:
            return "Windows 7 / Server 2008"
        if window > 16384:
            return "Modern Windows (10/11/Server 2022)"
        return "Windows System"
    else:
        return "Network Infrastructure (Cisco/Firewall)"

def get_location_data(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(f"http://ip-api.com/json/{ip}", headers=headers, timeout=2)
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "city": data.get("city"),
                "country": data.get("country"),
                "flag": get_flag(data.get("countryCode")),
                "isp": data.get("isp"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "org": data.get("org", "N/A")
            }
            ip_cache[ip] = result
            return result
    except:
        pass
    return None

async def broadcast(message):
    if connected_clients:
        await asyncio.gather(*[client.send(message) for client in connected_clients])

def display_and_broadcast(src_ip, packet, loc_data):
    proto = "UDP" if packet.haslayer(UDP) else "TCP"
    sport = packet.sport
    dport = packet.dport
    os_detail = get_detailed_os(packet)
    ttl = packet[IP].ttl
    window = packet[TCP].window if packet.haslayer(TCP) else "N/A"

    with print_lock:
        console.print(f"\n[bold white on red] TARGET LOCKED ({proto}) [/bold white on red] [bold yellow] {src_ip} [/bold yellow]")
        console.print(f"{loc_data['flag']} [bold white]LOCATION:[/bold white] [cyan]{loc_data['city']}, {loc_data['country']}[/cyan]")
        console.print(f"📡 [bold white]PROVIDER:[/bold white] [green]{loc_data['isp']}[/green] | [dim]{loc_data['org']}[/dim]")
        console.print(f"🧬 [bold white]SYSTEM  :[/bold white] [bold magenta]{os_detail}[/bold magenta]")
        console.print(f"📊 [bold white]METRICS :[/bold white] Port: {sport}->{dport} | TTL: {ttl} | Win: {window}")
        console.print("[red]" + "━" * 70 + "[/red]")

    ws_data = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "protocol": proto,
        "sport": sport,
        "dport": dport,
        "ttl": ttl,
        "window": window,
        "os_guess": os_detail,
        "location": loc_data
    }

    asyncio.run_coroutine_threadsafe(broadcast(json.dumps(ws_data)), loop)

    if args.log:
        with print_lock:
            with open(args.log, "a", encoding="utf-8") as f:
                f.write(json.dumps(ws_data, ensure_ascii=False) + "\n")

def packet_callback(packet):
    if not packet.haslayer(IP):
        return
    if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
        return

    src_ip = packet[IP].src

    if args.target and src_ip != args.target:
        return

    noise_isps = ["Microsoft", "Google", "Cloudflare", "Akamai", "Amazon", "Facebook"]
    if src_ip.startswith(("192.168", "127.", "10.", "172.", "169.254")):
        return

    future = executor.submit(get_location_data, src_ip)

    def on_location_ready(fut):
        loc_data = fut.result()
        if loc_data is None:
            return
        if any(noise in loc_data['isp'] for noise in noise_isps):
            return
        display_and_broadcast(src_ip, packet, loc_data)

    future.add_done_callback(on_location_ready)

async def websocket_handler(websocket):
    connected_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.remove(websocket)

async def start_websocket_server(port):
    async with websockets.serve(websocket_handler, "localhost", port):
        console.print(f"[green][+] WebSocket server running at ws://localhost:{port}[/green]")
        await asyncio.Future()

def run_websocket_server():
    global loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_websocket_server(args.port))

def main():
    banner = f"""
    [bold cyan]SHADOW TRACE ENGINE v{__version__}[/bold cyan]
    [bold white]---------------------------------------[/bold white]
    [bold green]DEVELOPED BY: {__author__.upper()}[/bold green]
    [dim]Live Dashboard Mode (WebSocket)[/dim]
    """
    console.print(Panel(banner, border_style="blue", expand=False))

    ws_thread = threading.Thread(target=run_websocket_server, daemon=True)
    ws_thread.start()

    # Open dashboard HTML file directly
    if not args.no_browser:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dashboard_path = os.path.join(script_dir, "dashboard.html")
        webbrowser.open(f"file://{dashboard_path}")

    filter_str = "ip"
    if args.target:
        filter_str = f"host {args.target}"
        console.print(f"[yellow][!] Filtering only traffic from: {args.target}[/yellow]")

    iface = args.interface if args.interface else None
    console.print(f"[green][+] Sniffing on interface: {iface or 'default'}[/green]")
    console.print("[green][+] Press Ctrl+C to stop.[/green]\n")
    console.print("[cyan][+] Dashboard opened in your browser.[/cyan]")
    console.print("[cyan][+] If it doesn't open, manually open dashboard.html[/cyan]\n")

    try:
        sniff(iface=iface, filter=filter_str, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        console.print(f"\n[bold red][!] Session terminated by {__author__}.[/bold red]")
        executor.shutdown(wait=False)

if __name__ == "__main__":
    main()
