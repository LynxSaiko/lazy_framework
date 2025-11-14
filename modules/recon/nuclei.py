# modules/recon/nuclei_scan.py
import subprocess
import shutil
import os
import re
import json
from typing import Dict, Any
from rich.console import Console
from rich.table import Table

MODULE_INFO = {
    "name": "Nuclei Scan (Full GUI)",
    "description": "Vulnerability scanner dengan Nuclei + dropdown templates & severity",
    "author": "LazyFramework",
    "rank": "Excellent",
    "category": "recon",
}

# === KATEGORI TEMPLATES RESMI ===
NUCLEI_CATEGORIES = [
    "exposures",
    "fuzzing", "takeovers", "dns", "file", "network", "ssl",
    "technologies", "default-logins", "iot", "panels",
    "token-spray", "workflow"
]

SEVERITY_LIST = ["critical", "high", "medium", "low", "info"]

OPTIONS = {
    "TARGET": {
        "default": "",
        "required": True,
        "description": "Target: URL, IP, atau file list[](http://site.com)",
    },
    "TEMPLATE": {
        "default": "",
        "required": False,
        "description": "Pilih kategori template (multi-select)",
        "choices": NUCLEI_CATEGORIES,
    },
    "SEVERITY": {
        "default": "critical,high,medium",
        "required": False,
        "description": "Filter severity (multi-select)",
        "choices": SEVERITY_LIST + ["all"],
    },
    "THREADS": {
        "default": "50",
        "required": False,
        "description": "Jumlah concurrency (1-200)",
    },
    "UPDATE": {
        "default": "no",
        "required": False,
        "description": "Update templates otomatis?",
        "choices": ["yes", "no"],
    },
}

console = Console()
SEVERITY_COLORS = {
    "critical": "bold red", "high": "red", "medium": "yellow",
    "low": "blue", "info": "cyan", "unknown": "white"
}

# === PATH TEMPLATES ===
TEMPLATES_DIR = os.path.expanduser("~/nuclei-templates")
DEFAULT_REPO = "https://github.com/projectdiscovery/nuclei-templates"

def _check_nuclei() -> bool:
    """Cek apakah nuclei ada"""
    if not shutil.which("nuclei"):
        console.print("[bold red][X] nuclei tidak ditemukan![/]")
        console.print("[dim]Install manual:[/]")
        console.print("  [dim]Termux: pkg install nuclei[/]")
        console.print("  [dim]Kali: sudo apt install nuclei[/]")
        console.print("  [dim]GitHub: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest[/]")
        return False
    return True

def _check_templates(update: bool = False) -> str:
    """Download/update templates + validasi kategori"""
    if not os.path.exists(TEMPLATES_DIR):
        console.print(f"[bold yellow][*] Templates tidak ada: {TEMPLATES_DIR}[/]")
        console.print("[dim]Cloning dari GitHub...[/]")
        try:
            subprocess.run(["git", "clone", "--depth=1", DEFAULT_REPO, TEMPLATES_DIR], check=True)
            console.print(f"[bold green][+] Templates di-download![/]")
        except Exception as e:
            console.print(f"[bold red][X] Gagal clone: {e}[/]")
            return None
    else:
        if update:
            console.print(f"[bold cyan][*] Update templates...[/]")
            try:
                subprocess.run(["git", "-C", TEMPLATES_DIR, "pull"], check=True)
                console.print("[bold green][+] Templates diperbarui![/]")
            except Exception as e:
                console.print(f"[bold red][X] Gagal update: {e}[/]")

    # Validasi kategori yang tersedia
    available = [cat for cat in NUCLEI_CATEGORIES if os.path.isdir(os.path.join(TEMPLATES_DIR, cat))]
    if not available:
        console.print("[bold red][X] Tidak ada kategori templates![/]")
        return None

    # Update choices di OPTIONS
    OPTIONS["TEMPLATE"]["choices"] = available
    return TEMPLATES_DIR

def run(session: Dict[str, Any], options: Dict[str, Any]):
    target = options.get("TARGET", "").strip()
    template_input = options.get("TEMPLATE", "").strip()
    severity_input = options.get("SEVERITY", "").strip()
    threads = options.get("THREADS", "50")
    do_update = options.get("UPDATE", "no").lower() == "yes"

    if not target:
        console.print("[bold red][X] TARGET wajib diisi![/]")
        return

    if not _check_nuclei():
        return

    templates_path = _check_templates(update=do_update)
    if not templates_path:
        return

    # === PROSES TEMPLATE (multi-select) ===
    available_templates = OPTIONS["TEMPLATE"]["choices"]
    selected_templates = [t.strip() for t in template_input.split(",") if t.strip()]
    invalid_templates = [t for t in selected_templates if t not in available_templates]
    if invalid_templates:
        console.print(f"[bold red][X] Template tidak tersedia: {', '.join(invalid_templates)}[/]")
        console.print(f"[dim]Tersedia: {', '.join(available_templates)}[/]")
        return

    # === PROSES SEVERITY (multi-select) ===
    selected_severity = []
    if severity_input and severity_input != "all":
        selected_severity = [s.strip().lower() for s in severity_input.split(",") if s.strip()]
        invalid_sev = [s for s in selected_severity if s not in SEVERITY_LIST]
        if invalid_sev:
            console.print(f"[bold red][X] Severity tidak valid: {', '.join(invalid_sev)}[/]")
            return

    # === BUILD COMMAND ===
    cmd = ["nuclei", "-t", templates_path]

    if os.path.isfile(target):
        cmd.extend(["-l", target])
    else:
        cmd.extend(["-target", target])

    if selected_templates:
        cmd.extend(["-tags", ",".join(selected_templates)])

    if selected_severity:
        cmd.extend(["-severity", ",".join(selected_severity)])

    cmd.extend(["-c", threads, "-json", "-silent"])

    # === TAMPILKAN CONFIG ===
    table = Table(title="[bold cyan]Nuclei Scan Config[/]", box=None)
    table.add_column("Parameter", style="bold green")
    table.add_column("Value")
    table.add_row("Target", target)
    table.add_row("Templates", ", ".join(selected_templates) if selected_templates else "[dim]all[/]")
    table.add_row("Severity", ", ".join(selected_severity) if selected_severity else "[dim]all[/]")
    table.add_row("Threads", threads)
    table.add_row("Templates Path", templates_path)
    table.add_row("Update", "Yes" if do_update else "No")
    console.print(table)

    console.print(f"[dim]Command: {' '.join(cmd)}[/]\n")

    # === JALANKAN NUCLEI ===
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
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                info = data.get("info", {})
                sev = info.get("severity", "unknown").lower()
                findings.append({
                    "template": data.get("template-id", "unknown"),
                    "severity": sev,
                    "name": info.get("name", "No name"),
                    "host": data.get("host", "unknown"),
                    "matched": data.get("matched", "unknown")
                })

                color = SEVERITY_COLORS.get(sev, "white")
                console.print(f"[{color}][{sev.upper()}][/] {info.get('name', 'Unknown')}")
                console.print(f"   [dim]Template: {data.get('template-id')}[/]")
                if data.get("matched") != data.get("host"):
                    console.print(f"   [dim]Matched: {data.get('matched')}[/]")

            except json.JSONDecodeError:
                console.print(f"[dim]{line}[/]")

        process.wait()
        _show_summary(findings)

    except Exception as e:
        console.print(f"[bold red][X] Error: {e}[/]")

def _show_summary(findings):
    if not findings:
        console.print("\n[bold white]Tidak ada vulnerability ditemukan.[/]")
        return

    count = {sev: 0 for sev in SEVERITY_LIST}
    count["unknown"] = 0
    for f in findings:
        sev = f["severity"]
        count[sev] = count.get(sev, 0) + 1

    # Summary table
    table = Table(title="[bold magenta]Scan Summary[/]")
    table.add_column("Severity", width=10)
    table.add_column("Count", width=8)
    for sev, num in count.items():
        if num > 0 and sev != "unknown":
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(f"[{color}]{sev.upper()}[/]", str(num))
    if count["unknown"] > 0:
        table.add_row("[white]UNKNOWN[/]", str(count["unknown"]))
    console.print(table)

    # Detail table
    detail = Table(title="[bold cyan]Top Vulnerabilities[/]")
    detail.add_column("Severity", width=10)
    detail.add_column("Name")
    detail.add_column("Template")
    for f in findings[:20]:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        detail.add_row(
            f"[{ get_color(f['severity']) }]{f['severity'].upper()}[/]",
            f["name"],
            f["template"]
        )
    if len(findings) > 20:
        detail.add_row("...", f"[dim]+{len(findings)-20} more[/]")
    console.print(detail)

def get_color(sev):
    return SEVERITY_COLORS.get(sev.lower(), "white")
