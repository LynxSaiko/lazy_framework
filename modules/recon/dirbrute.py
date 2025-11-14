# modules/recon/dirbuster.py
import subprocess
import shutil
import os
import re
from typing import Dict, Any
from rich.console import Console
from rich.table import Table

MODULE_INFO = {
    "name": "DirBuster",
    "description": "Directory brute-force",
    "author": "LazyFramework",
    "rank": "Excellent",
    "category": "recon",
}

OPTIONS = {
    "URL": {
        "default": "",
        "required": True,
        "description": "Target URL http/https",
    },
    "WORDLIST": {
        "default": "common.txt",
        "required": True,
        "description": "Path wordlist (contoh: /usr/share/wordlists/dirb/common.txt)",
    },
    "THREADS": {
        "default": "20",
        "required": False,
        "description": "threads (1-100)",
    },
    "EXTENSIONS": {
        "default": "php,html,txt,js",
        "required": False,
        "description": "Ekstensi file",
    },
    "TOOL": {
        "default": "auto",
        "required": False,
        "description": "tool: auto, dirb, dirsearch, gobuster",
        "choices": ["auto", "dirbuster-ng", "dirsearch", "gobuster"],
    },
}

COMMON_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/data/data/com.termux/files/usr/share/wordlists/dirb/common.txt",
    "/data/data/com.termux/files/usr/share/seclists/Discovery/Web-Content/common.txt",
]

console = Console()

def _find_tool(choice: str) -> str:
    tools = ["dirsearch", "gobuster", "dirbuster-ng"]
    if choice != "auto":
        if shutil.which(choice):
            return choice
        else:
            console.print(f"[bold red][X] Tool '{choice}' tidak ditemukan! Install manual.[/]")
            return None

    for tool in tools:
        if shutil.which(tool):
            return tool
    return None

def _find_wordlist(path: str) -> str:
    """Cari wordlist, jika tidak ada → sarankan path umum"""
    if os.path.exists(path):
        return path
    for common in COMMON_WORDLISTS:
        if os.path.exists(common):
            console.print(f"[dim]Wordlist ditemukan: {common}[/]")
            return common
    return None

def run(session: Dict[str, Any], options: Dict[str, Any]):
    url = options.get("URL", "").strip()
    wordlist_input = options.get("WORDLIST", "").strip()
    threads = options.get("THREADS", "20")
    extensions = options.get("EXTENSIONS", "").strip()
    tool_choice = options.get("TOOL", "auto").lower()

    # === VALIDASI URL ===
    if not url.startswith(("http://", "https://")):
        console.print("[bold red][X] URL harus dimulai dengan http:// atau https://[/]")
        return
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    # === DETEKSI TOOL (TANPA INSTALL) ===
    tool = _find_tool(tool_choice)
    if not tool:
        console.print("[bold red][X] Tidak ada tool yang tersedia![/]")
        console.print("[dim]Install salah satu: dirsearch, gobuster, atau dirb[/]")
        console.print("[dim]Contoh (Termux): pkg install dirsearch[/]")
        console.print("[dim]Contoh (Kali): sudo apt install dirb[/]")
        return

    # === CARI WORDLIST ===
    wordlist = _find_wordlist(wordlist_input)
    if not wordlist:
        console.print(f"[bold red][X] Wordlist tidak ditemukan: {wordlist_input}[/]")
        console.print("[dim]Coba salah satu path berikut:[/]")
        for p in COMMON_WORDLISTS:
            console.print(f"  [dim]{p}[/]")
        console.print("[dim]Atau download manual dari SecLists[/]")
        return

    # === BUILD COMMAND ===
    cmd = []
    if tool == "dirsearch":
        cmd = [tool, "-u", url, "-w", wordlist, "-t", threads, "--format=plain"]
        if extensions:
            cmd.extend(["-e", extensions])
    elif tool == "gobuster":
        cmd = [tool, "dir", "-u", url, "-w", wordlist, "-t", threads, "-q"]
        if extensions:
            cmd.append("-x")
            cmd.extend([e.strip() for e in extensions.split(",") if e.strip()])
    elif tool == "dirbuster-ng":
        cmd = [tool, url, wordlist, "-r", "-S"]
        if extensions:
            cmd.append("-X")
            cmd.append("." + ",.".join([e.strip() for e in extensions.split(",")]))

    # === TAMPILKAN CONFIG ===
    table = Table(title="[bold cyan]DirBuster Config[/]", box=None)
    table.add_column("Parameter", style="bold green")
    table.add_column("Value")
    table.add_row("URL", url)
    table.add_row("Tool", f"[bold yellow]{tool}[/]")
    table.add_row("Wordlist", wordlist)
    table.add_row("Threads", threads)
    table.add_row("Extensions", extensions or "[dim]None[/]")
    console.print(table)

    console.print(f"[dim]Command: {' '.join(cmd)}[/]\n")

    # === JALANKAN TOOL ===
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        findings = []
        for line in process.stdout:
            line = line.rstrip()
            if not line:
                continue

            # Parse output berdasarkan tool
            parsed = _parse_line(tool, line)
            if parsed:
                status, path, size = parsed
                findings.append(parsed)
                color = "green" if status == "200" else "yellow" if status in ["301", "302"] else "red"
                console.print(f"[{color}][+]{status}[/] {path} [dim]({size})[/]")

        process.wait()
        _show_summary(findings)

    except FileNotFoundError:
        console.print(f"[bold red][X] Tool '{tool}' tidak ditemukan! Install manual.[/]")
    except Exception as e:
        console.print(f"[bold red][X] Error: {e}[/]")

def _parse_line(tool: str, line: str):
    """Parse satu baris output"""
    if tool == "dirsearch" and ("[200]" in line or "[301]" in line or "[403]" in line):
        parts = line.split()
        if len(parts) >= 3:
            status = parts[0].strip("[]")
            path = parts[-1]
            size = parts[1].strip("[]") if len(parts) > 3 else ""
            return status, path, size
    elif tool == "gobuster" and line.startswith("/"):
        parts = line.split()
        if len(parts) >= 3:
            path = parts[0]
            status = parts[1].strip("[]")
            size = parts[2].strip("()")
            return status, path, size
    elif tool == "dirb" and "CODE:" in line:
        parts = line.split()
        if len(parts) >= 3:
            status = parts[1]
            path = " ".join(parts[2:])
            return status, path, ""
    return None

def _show_summary(findings):
    if not findings:
        console.print("\n[bold white]Tidak ada direktori ditemukan.[/]")
        return

    table = Table(title="[bold magenta]Scan Summary[/]")
    table.add_column("Status", width=6)
    table.add_column("Path")
    table.add_column("Size", width=8)

    count_200 = 0
    for status, path, size in findings[:30]:
        if status == "200":
            table.add_row("[green]200[/]", path, size)
            count_200 += 1
        elif status in ["301", "302"]:
            table.add_row("[yellow]302[/]", path, size)
        else:
            table.add_row("[red]403[/]", path, size)

    if len(findings) > 30:
        table.add_row("...", f"[dim]+{len(findings)-30} more[/]")

    console.print(table)
    console.print(f"\n[bold]Found: [green]{count_200} 200 OK[/] | Total: {len(findings)}[/]")