#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import shutil
import socket
import re
import sys
from typing import Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from tqdm import tqdm

console = Console()

# ==================== MODULE INFO ====================
MODULE_INFO = {
    "name": "Nmap Super Scan (Fast)",
    "author": "Lazy Framework",
    "description": "Nmap with real progress, DNS resolve, -Pn, default top 100 ports, full parsing.",
    "rank": "Excellent",
    "dependencies": [],
    "platform": "multi",
    "arch": "multi"
}

# ==================== MODES ====================
SCAN_MODES = {
    "tcp_syn":      {"flag": "-sS", "desc": "TCP SYN",      "class": "TCP",       "root": True},
    "tcp_connect":  {"flag": "-sT", "desc": "TCP Connect",  "class": "TCP",       "root": False},
    "tcp_ack":      {"flag": "-sA", "desc": "TCP ACK",      "class": "TCP",       "root": True},
    "tcp_fin":      {"flag": "-sF", "desc": "TCP FIN",      "class": "TCP",       "root": True},
    "tcp_null":     {"flag": "-sN", "desc": "TCP NULL",     "class": "TCP",       "root": True},
    "tcp_xmas":     {"flag": "-sX", "desc": "TCP Xmas",     "class": "TCP",       "root": True},
    "tcp_window":   {"flag": "-sW", "desc": "TCP Window",   "class": "TCP",       "root": True},
    "tcp_maimon":   {"flag": "-sM", "desc": "TCP Maimon",   "class": "TCP",       "root": True},
    "udp_scan":     {"flag": "-sU", "desc": "UDP Scan",     "class": "UDP",       "root": True},
    "udp_version":  {"flag": "-sUV","desc": "UDP + Ver",    "class": "UDP",       "root": True},
    "sctp_init":    {"flag": "-sY", "desc": "SCTP INIT",    "class": "SCTP",      "root": True},
    "sctp_cookie":  {"flag": "-sZ", "desc": "SCTP COOKIE",  "class": "SCTP",      "root": True},
    "ping_scan":    {"flag": "-sn", "desc": "Ping Only",    "class": "Discovery", "root": False},
    "arp_ping":     {"flag": "-PR", "desc": "ARP Ping",     "class": "Discovery", "root": False},
    "version_detect": {"flag": "-sV", "desc": "Version",    "class": "Advanced", "root": False},
    "os_detect":      {"flag": "-O",  "desc": "OS Detect",  "class": "Advanced", "root": True},
    "script_default": {"flag": "-sC", "desc": "NSE Scripts","class": "Advanced", "root": False},
    "aggressive":     {"flag": "-A",  "desc": "Aggressive", "class": "Advanced", "root": True},
    "ipv6":           {"flag": "-6",  "desc": "IPv6",       "class": "Advanced", "root": False},
    "traceroute":     {"flag": "--traceroute", "desc": "Trace hop path to each hostSCAN TECHNIQUES", "class": "TCP",  "root": True},
}

MODE_CHOICES = list(SCAN_MODES.keys()) + ["list"]

OPTIONS = {
    "TARGET": {"description": "Target Ip address/dns", "required": True, "default": ""},
    "PORTS":  {"description": "Ports", "required": False, "default": ""},
    "MODE":   {"description": "Mode Scanners", "required": True, "default": "", "choices": MODE_CHOICES},
    "OUTPUT": {"description": "Save XML", "required": False, "default": ""}
}

# ==================== HELPERS ====================
def _is_root():
    return os.geteuid() == 0
def _resolve(target):
    target = target.strip()
    if re.match(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$", target):
        return target
    try:
        ip = socket.gethostbyname(target)
        console.print(f"[cyan][*] {target} → {ip}[/]")
        return ip
    except:
        raise ValueError("DNS resolve failed")

def _show_modes():
    table = Table(box=box.DOUBLE)
    table.add_column("Class", style="bold cyan")
    table.add_column("Mode", style="bold yellow", overflow="fold")
    table.add_column("Flag", style="green")
    table.add_column("Root", justify="center")
    table.add_column("Desc")
    for k, v in SCAN_MODES.items():
        root = "[red]Yes[/]" if v["root"] else "[green]No[/]"
        table.add_row(v["class"], k, v["flag"], root, v["desc"])
    console.print(Panel(table, title="Nmap Modes"))
    console.print("[yellow]Use 'list' in MODE[/]")

def _build_cmd(options):
    target = _resolve(options["TARGET"])
    ports = options.get("PORTS", "-p-").strip()  # Default to scanning all ports
    mode_key = options.get("MODE", "").lower()
    output = options.get("OUTPUT", "")

    if mode_key == "list":
        _show_modes()
        return None

    if mode_key not in SCAN_MODES:
        raise ValueError("Invalid MODE")

    flag = SCAN_MODES[mode_key]["flag"]
    if SCAN_MODES[mode_key]["root"] and not _is_root():
        console.print(f"[bold yellow][!] {mode_key} needs root. Still running...[/]")
        if mode_key == "tcp_syn":
            mode_key = "tcp_connect"  # Switch to tcp_connect if not root
            flag = SCAN_MODES[mode_key]["flag"]

    # General scan settings
    smart = " -T4 --min-hostgroup 32 --min-parallelism 64 --host-timeout 60s"
    if "ping_scan" not in mode_key:
        smart += " -Pn"
    elif "udp" in mode_key:
        smart += " -Pn"
    elif "tcp" in mode_key:
        smart += " -Pn"
    if "port_scan" in options:
        ports = "-p-"  # Scan all ports

    # Build the nmap command
    cmd = ["nmap", "-v", flag]
    
    if ports != "-p-" and ports:
       cmd += ["-p", ports]
    cmd += [target]  # Add the target (IP/hostname)
    cmd += smart.split()  # Add additional options
    
    if output:
        cmd += ["-oX", output]  # Add output XML file if specified
    
    # Convert the cmd list to a string for execution
    cmd_str = " ".join(cmd)
    return cmd_str

# ==================== SCAN ====================
def _run_scan(cmd):
    pbar = tqdm(total=100, desc="Scanning", bar_format="{l_bar}{bar}| {percentage:3.0f}%", ncols=50, file=sys.stdout)
    pbar.clear()

    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)

    output = []
    last_pct = 0
    hosts = 0
    open_ports = 0

    for line in proc.stdout:
        output.append(line)
        line = line.strip()

        m = re.search(r"(\d+(?:\.\d+)?)%", line)
        if m:
            pct = int(float(m.group(1)))
            if pct > last_pct:
                pbar.update(pct - last_pct)
                last_pct = pct

        if "Nmap scan report for" in line:
            hosts += 1
        if re.search(r"\d+/(tcp|udp)\s+open", line):
            open_ports += 1

    proc.wait()
    pbar.update(100 - last_pct)
    pbar.close()
    return "".join(output), hosts, open_ports

# ==================== DISPLAY ====================
def _show_results(raw, target, mode_key):
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Host", overflow="fold")
    table.add_column("Port", style="yellow")
    table.add_column("State", style="green")
    table.add_column("Service", overflow="fold")

    host = target
    hosts = 0
    open_ports = 0
    if mode_key == "tcp_syn" and not _is_root():
        console.print(f"[red]Warning: TCP SYN scan requires root privileges! Switching to TCP Connect scan.[/]")

    for line in raw.splitlines():
        if "Nmap scan report for" in line:
            m = re.search(r"for (.+?)(?: \(|$)", line)
            host = m.group(1) if m else target
            hosts += 1
        elif re.search(r"\d+/(tcp|udp)", line):
            parts = line.split()
            if len(parts) >= 3:
                table.add_row(host, parts[0], parts[1], " ".join(parts[2:]))
                open_ports += 1

    if table.row_count:
        console.print(Panel(table, border_style="green"))
    else:
        console.print("[yellow]No open ports. Try: scanme.nmap.org or top 1000[/]")

    # Make sure hosts and open_ports are integers before displaying them
    console.print(f"\n[bold cyan]Summary:[/]")
    console.print(f"  • Target: [white]{target}[/]")
    console.print(f"  • Hosts up: [yellow]{hosts if isinstance(hosts, int) else 0}[/]")
    console.print(f"  • Open ports: [green]{open_ports if isinstance(open_ports, int) else 0}[/]")

# ==================== RUN ====================
def run(session: Dict[str, Any], options: Dict[str, Any]):
    console.print("[bold blue][*] Nmap Super Scan...[/]")

    if not shutil.which("nmap"):
        console.print("[red]nmap not found![/]")
        return

    try:
        cmd = _build_cmd(options)
        if not cmd:
            return

        console.print(f"[dim]{cmd}[/]")
        output, _, _ = _run_scan(cmd)
        _show_results(output, options["TARGET"], options["MODE"])
        console.print("\n[bold green][Success] Done![/]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
