# modules/recon/wpscan.py

import subprocess
import shutil
import os
from typing import Dict, Any
from rich.table import Table
from rich import box
from rich.console import Console

console = Console()

MODULE_INFO = {
    "name": "WPScan Scanner",
    "description": "WordPress vulnerability & enumeration scanner",
    "author": "LazyFramework",
    "rank": "Excellent",
    "platform": "Linux, Windows, macOS",
    "category": "recon",
}

# SEMUA OPTIONS HURUF BESAR + target → URL
OPTIONS = {
    "URL": {
        "default": "",
        "required": True,
        "description": "Target WordPress URL[](https://example.com)",
    },
    "MODE": {
        "default": "QUICK",
        "required": True,
        "description": "Scan intensity",
        "choices": ["QUICK", "STANDARD", "AGGRESSIVE", "ENUMERATE", "BRUTEFORCE"],
    },
    "WORDLIST": {
        "default": "",
        "required": False,
        "description": "Wordlist path (for BRUTEFORCE mode)",
    },
    "MAX_THREADS": {
        "default": "5",
        "required": False,
        "description": "Max threads (1-50, default: 5)",
    },
    "PROXY": {
        "default": "",
        "required": False,
        "description": "Proxy (http://IP:PORT or socks5://...)",
    },
    "API_TOKEN": {
        "default": "",
        "required": False,
        "description": "WPScan API Token (get free at wpscan.com)",
    },
}

def run(session: Dict[str, Any], options: Dict[str, Any]):
    url = options.get("URL", "").strip().lower()
    mode = options.get("MODE", "QUICK").lower()
    wordlist = options.get("WORDLIST", "")
    max_threads = str(options.get("MAX_THREADS", "5"))
    proxy = options.get("PROXY", "")
    api_token = options.get("API_TOKEN", "")

    # Normalize URL
    if not url.startswith("http"):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"

    # Detect wpscan
    wpscan_path = shutil.which("wpscan")
    if not wpscan_path:
        console.print("[bold red][X] WPScan not found! Install: gem install wpscan[/]")
        return

    # Build command
    cmd = [wpscan_path, "--url", url, "--max-threads", max_threads, "--no-banner", "--format", "cli"]

    if proxy:
        cmd.extend(["--proxy", proxy])
    if api_token:
        cmd.extend(["--api-token", api_token])

    # Mode mapping (case-insensitive)
    mode_map = {
        "quick": ["--detection-mode", "passive"],
        "standard": ["--enumerate", "vp,vt,u"],
        "aggressive": ["--enumerate", "vp,vt,u,cb,dbe", "--plugins-detection", "aggressive"],
        "enumerate": ["--enumerate"],
        "bruteforce": ["--passwords", wordlist, "--usernames", "admin"] if wordlist and os.path.exists(wordlist) else None,
    }

    if mode == "bruteforce" and (not wordlist or not os.path.exists(wordlist)):
        console.print("[bold red][X] WORDLIST required for BRUTEFORCE mode![/]")
        return

    mode_cmd = mode_map.get(mode)
    if mode_cmd:
        cmd.extend(mode_cmd)

    cmd.append("--random-user-agent")

    # === TAMPILKAN KONFIGURASI ===
    _show_scan_info(url, mode.upper(), max_threads, proxy, api_token, wordlist)

    console.print(f"[dim]Running: {' '.join(cmd)}[/]\n")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        findings = []
        for line in process.stdout:
            line = line.rstrip()
            if not line:
                continue

            if "[!]" in line:
                console.print(f"[bold red]{line}[/]")
                findings.append(("VULN", line.split("[!]", 1)[1].strip()))
            elif "[+]" in line:
                console.print(f"[bold green]{line}[/]")
                findings.append(("INFO", line.split("[+]", 1)[1].strip()))
            elif "[i]" in line:
                console.print(f"[bold yellow]{line}[/]")
            else:
                console.print(line)

        process.wait()
        _show_summary(findings, process.returncode == 0)

    except Exception as e:
        console.print(f"[bold red][X] Error: {e}[/]")

# === TABEL KONFIGURASI ===
def _show_scan_info(url, mode, max_threads, proxy, api_token, wordlist):
    term_width = shutil.get_terminal_size().columns
    is_small = term_width < 80

    table = Table(
        title="[bold cyan]WPScan Configuration[/]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        expand=not is_small,
        width=term_width - 4 if is_small else None
    )

    if is_small:
        table.add_column("Key", style="dim", width=12)
        table.add_column("Value", overflow="fold")
    else:
        table.add_column("Parameter", style="bold green", width=15)
        table.add_column("Value", overflow="fold")

    table.add_row("URL", url)
    table.add_row("MODE", f"[bold yellow]{mode}[/]")
    table.add_row("MAX_THREADS", max_threads)
    table.add_row("PROXY", proxy or "[dim]None[/]")
    table.add_row("API_TOKEN", "[green]Yes[/]" if api_token else "[dim]No[/]")
    table.add_row("WORDLIST", wordlist or "[dim]N/A[/]")

    console.print(table)

# === TABEL RINGKASAN ===
def _show_summary(findings, success):
    if not findings:
        console.print("\n[bold white]No significant findings.[/]")
        return

    term_width = shutil.get_terminal_size().columns
    is_small = term_width < 80

    table = Table(
        title="[bold magenta]Scan Summary[/]",
        box=box.DOUBLE_EDGE if not is_small else box.SIMPLE,
        show_header=True,
        header_style="bold white",
    )

    if is_small:
        table.add_column("Type", width=5)
        table.add_column("Detail", overflow="fold")
    else:
        table.add_column("Type", width=8, justify="center")
        table.add_column("Finding", overflow="fold")

    vuln_count = sum(1 for t, _ in findings if t == "VULN")
    info_count = len(findings) - vuln_count

    for typ, text in findings[:20]:
        if typ == "VULN":
            table.add_row("[red]VULN[/]", text)
        else:
            table.add_row("[green]INFO[/]", text)

    if len(findings) > 20:
        table.add_row("...", f"[dim]{len(findings) - 20} more...[/]")

    console.print(table)
    console.print(f"\n[bold]Vulnerabilities: [red]{vuln_count}[/] | Info: [green]{info_count}[/][/]")