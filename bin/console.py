#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, shlex, importlib.util, re, platform, time, random, itertools, threading, shutil, textwrap
import socket
import select
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.markup import escape

from core import Search, get_random_banner, load_banners_from_folder

console = Console()
import builtins
builtins.console = console

BASE_DIR = Path(__file__).parent.parent 
MODULE_DIR, EXAMPLES_DIR, BANNER_DIR = BASE_DIR / "modules", BASE_DIR / "examples", BASE_DIR / "banner"
METADATA_READ_LINES = 120

@dataclass
class ModuleInstance:
    name: str
    module: Any
    options: Dict[str, Any] = field(default_factory=dict)
    def set_option(self, key, value):
        if key not in self.module.OPTIONS: raise KeyError(f"Unknown option '{key}'")
        self.options[key] = value
    def get_options(self):
        if hasattr(self.module, "OPTIONS"):
            return {k: {"value": self.options.get(k, v.get("default")), **v} for k, v in self.module.OPTIONS.items()}
        return {}

    def run(self, session): return self.module.run(session, self.options)

class LazyFramework:
    def __init__(self):
        self.modules, self.metadata = {}, {}
        self.loaded_module: Optional[ModuleInstance] = None
        self.session = {"user": os.getenv("USER", "unknown")}
        self.scan_modules()
        self.auto_cleanup()
        self.external_tools = self._scan_external_tools()

    def _scan_external_tools(self):
        tools = {
            'nmap': shutil.which('nmap'),
            'metasploit': shutil.which('msfconsole'),
            'sqlmap': shutil.which('sqlmap'),
            'nikto': shutil.which('nikto'),
            'gobuster': shutil.which('gobuster'),
            'hydra': shutil.which('hydra'),
            'john': shutil.which('john'),
        }
        return {k: v for k, v in tools.items() if v}

    def scan_modules(self):
        self.modules.clear()
        self.metadata.clear()
        self.auto_run_modules()
        valid_extensions = [".py", ".cpp", ".c", ".rb", ".php"]
        for folder, prefix in ((MODULE_DIR, "modules"),):
            for p in folder.rglob("*"):
                if p.is_dir(): continue
                if p.suffix not in valid_extensions: continue
                if p.name == "__init__.py": continue
                if "__pycache__" in p.parts or p.suffix in ['.pyc', '.pyo']: continue
                rel = str(p.relative_to(folder)).replace(os.sep, "/")
                key = f"{prefix}/{rel[:-len(p.suffix)]}" if p.suffix else f"{prefix}/{rel}"
                if key.endswith('.py'): key = key[:-3]
                self.modules[key] = p
                self.metadata[key] = self._read_meta(p)
        self.auto_run_modules()
     
    def auto_run_modules(self):
        if not self.modules:
            #console.print("No modules found.")
            return
        #console.print(f"[bold green][*][/bold green] Scanning module tree... {len(self.modules)} module(s)")
        for key, path in sorted(self.modules.items()):
            #rel = path.relative_to(BASE_DIR)
            if path.suffix == ".py":
                try:
                    compile(path.read_bytes(), str(path), 'exec')
                    #console.print(f"  OK  {rel}")
                except Exception as e:
                    #console.print(f"[bold red][!][/bold red] No modules found during scan {rel}  {e}")
                    pass
            else:
                pass
                #console.print(f"  FILE {rel}")

    def _read_meta(self, path):
        data = {"description": "(No description available)", "options": [], "dependencies": [], "rank": "Normal"}
        try:
            text = "".join(path.open("r", encoding="utf-8", errors="ignore").readlines()[:METADATA_READ_LINES])
            if (m_info := re.search(r"MODULE_INFO\s*=\s*{([^}]+)}", text, re.DOTALL)):
                content = m_info.group(1)
                if (m_desc := re.search(r"(?:'description'|\"description\")\s*:\s*['\"]([^'\"]+)['\"]", content)):
                    data["description"] = m_desc.group(1).strip()
                if (m_rank := re.search(r"(?:'rank'|\"rank\")\s*:\s*['\"]([^'\"]+)['\"]", content)):
                    data["rank"] = m_rank.group(1).strip()
                if (m_deps := re.search(r"(?:'dependencies'|\"dependencies\")\s*:\s*\[([^\]]+)\]", content)):
                    deps_str = m_deps.group(1)
                    dependencies = re.findall(r"['\"]([^'\"]+)['\"]", deps_str)
                    data["dependencies"] = [dep.strip() for dep in dependencies if dep.strip()]
            if (mo := re.search(r"OPTIONS\s*=\s*{([^}]*)}", text, re.DOTALL)):
                data["options"] = re.findall(r"['\"]([A-Za-z0-9_]+)['\"]\s*:", mo.group(1))
        except Exception:
            pass
        return data

    def _check_dependencies(self, dependencies: List[str]) -> Dict[str, bool]:
        results = {}
        for dep in dependencies:
            clean_dep = re.split(r'[><=!]', dep)[0].strip().lower()
            if clean_dep == "pyinstaller":
                results[dep] = shutil.which("pyinstaller") is not None
                continue
            import_names = self._generate_import_names(clean_dep)
            success = False
            for name in import_names:
                if importlib.util.find_spec(name) is not None:
                    results[dep] = True
                    success = True
                    break
            if not success:
                results[dep] = False
        return results

    def _generate_import_names(self, package_name: str) -> List[str]:
        names = [package_name]
        if '-' in package_name: names.append(package_name.replace('-', '_'))
        if '.' in package_name: names.append(package_name.replace('.', '_'))
        mappings = {
            'beautifulsoup4': ['bs4'], 'pillow': ['PIL'], 'pyyaml': ['yaml'], 'opencv-python': ['cv2'],
            'requests': ['requests'], 'scapy': ['scapy'], 'cryptography': ['cryptography']
        }
        if package_name in mappings: names.extend(mappings[package_name])
        return list(dict.fromkeys(names))

    def cmd_use(self, args):
        if not args:
            console.print("Usage: use <module>", style="bold red")
            return
        user_key = args[0].strip()
        if user_key.lower().endswith('.py'): user_key = user_key[:-3]
        variations = [user_key, f"modules/{user_key}"]
        if user_key.startswith('modules/'): variations.insert(0, user_key); variations.append(user_key[8:])
        key = next((v for v in variations if v in self.modules), None)
        if not key:
            frag = user_key.split('/')[-1].lower()
            candidates = [k for k in self.modules.keys() if frag in k.lower() or k.lower().endswith('/' + frag)]
            if candidates:
                console.print(f"Module '{user_key}' not found. Did you mean:", style="yellow")
                for c in candidates[:8]: console.print("  " + c)
            else:
                console.print(f"Module '{user_key}' not found.", style="red")
            return

        path = self.modules[key]
        try:
            module_dir = path.parent
            pycache_path = module_dir / "__pycache__"
            self._delete_pycache_folder(pycache_path, "Pre-cleanup")

            spec = importlib.util.spec_from_file_location(key.replace('/', '_'), path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            self._delete_pycache_folder(pycache_path, "Post-cleanup")

            meta = getattr(mod, "MODULE_INFO", {})
            dependencies = meta.get("dependencies", [])
            if dependencies:
                dep_results = self._check_dependencies(dependencies)
                missing_deps = [dep for dep, available in dep_results.items() if not available]
                if missing_deps:
                    console.print(f"[yellow]Warning: Missing dependencies for module '{key}':[/yellow]")
                    for dep in missing_deps:
                        console.print(f"  [red]{dep}[/red] - not installed")
                    console.print(f"\n[yellow]Install missing dependencies with: pip install {' '.join(missing_deps)}[/yellow]")

            inst = ModuleInstance(key, mod)
            for k, meta_opt in getattr(mod, "OPTIONS", {}).items():
                if "default" in meta_opt:
                    inst.options[k] = meta_opt["default"]
            self.loaded_module = inst
            console.print(Panel(f"[*] Reloading modules from all [*][bold]{key}[/bold]", style="green"))
        except Exception as e:
            console.print(f"[*] Reloading Error modules from all [*] {escape(str(e))}", style="bold red")

    def auto_cleanup(self):
        cleaned_count = 0
        CORE_DIRS = [BASE_DIR / "bin", BASE_DIR / "core"]
        for d in CORE_DIRS:
            pycache_path = d / "__pycache__"
            if self._delete_pycache_folder(pycache_path, "Manual Cleanup"):
                cleaned_count += 1
        for p in MODULE_DIR.rglob("__pycache__"):
            if self._delete_pycache_folder(p, "Manual Cleanup"):
                 cleaned_count += 1

    def _delete_pycache_folder(self, pycache_path: Path, action_name: str):
        if pycache_path.is_dir():
            try:
                for item in pycache_path.iterdir():
                    if item.is_file(): os.unlink(item)
                os.rmdir(pycache_path)
                return True
            except Exception:
                return False
        return False

    def cmd_run(self, args):
        if not self.loaded_module:
            console.print("No module loaded.", style="red")
            return
        mod = self.loaded_module.module
        meta = getattr(mod, "MODULE_INFO", {})
        dependencies = meta.get("dependencies", [])
        if dependencies:
            dep_results = self._check_dependencies(dependencies)
            missing_deps = [dep for dep, available in dep_results.items() if not available]
            if missing_deps:
                console.print(f"[red]Error: Missing dependencies: {', '.join(missing_deps)}[/red]")
                console.print(f"[yellow]Install with: pip install {' '.join(missing_deps)}[/yellow]")
                return
        try:
            self.loaded_module.run(self.session)
        except Exception as e:
            console.print(f"Run error: {escape(str(e))}", style="red")

    def cmd_help(self, args):
        commands = [
            ("show modules", "Show all available modules"),
            ("show recon", "Show reconnaissance modules"),
            ("show strike", "Show strike/exploitation modules"),
            ("show hold", "Show hold/persistence modules"),
            ("show ops", "Show operations modules"),
            ("show payloads", "Show available payload modules"),
            ("use <module>", "Load a module by name"),
            ("info", "Show information about the current module"),
            ("options", "Show options for current module"),
            ("set <option> <value>", "Set module option"),
            ("run", "Run current module"),
            ("back", "Unload module"),
            ("search <keyword>", "Search modules"),
            ("scan", "Rescan modules"),
            ("banner reload|list", "Reload/list banner files"),
            ("cd <dir>", "Change working directory"),
            ("ls", "List current directory"),
            ("clear", "Clear terminal screen"),
            ("exit / quit", "Exit the program"),
        ]
        table = Table(title="Core Commands", box=box.SIMPLE_HEAVY)
        table.add_column("Command", style="bold white")
        table.add_column("Description", style="white")
        for cmd, desc in commands:
            table.add_row(cmd, desc)
        panel = Panel(table, title="", border_style="white", expand=True)
        console.print(panel)

    def cmd_payloads(self, args):
        payload_modules = {}
        for key, path in self.modules.items():
            if not key.startswith("modules/"): continue
            parts = key.split('/')
            if not (("payload" in parts) or ("payloads" in parts)): continue
            payload_modules[key] = self.metadata.get(key, {})
        if not payload_modules:
            console.print("No payload modules found under 'modules/'.", style="yellow")
            return
        table = Table(title="Available Payloads", box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("Payload", style="bold cyan", width=30)
        table.add_column("Type", style="yellow", width=15)
        table.add_column("Platform", style="green", width=12)
        table.add_column("Arch", style="magenta", width=10)
        table.add_column("Rank", style="red", width=8)
        table.add_column("Description", style="white", min_width=20)
        for key, meta in sorted(payload_modules.items()):
            display_name = key[len("modules/"):]
            kl = key.lower()
            payload_type = "unknown"
            if "meterpreter" in kl: payload_type = "meterpreter"
            elif "shell" in kl: payload_type = "shell"
            elif "reverse" in kl: payload_type = "reverse"
            elif "bind" in kl: payload_type = "bind"
            elif "staged" in kl: payload_type = "staged"
            elif "stageless" in kl: payload_type = "stageless"
            platform_info = meta.get("platform", "multi")
            if isinstance(platform_info, str): platform_info = platform_info.capitalize()
            arch = meta.get("arch", "multi")
            rank = meta.get("rank", "Normal")
            description = meta.get("description", "No description available")
            table.add_row(display_name, payload_type, str(platform_info), str(arch), str(rank), description)
        total_payloads = len(payload_modules)
        payload_types = {}
        platforms = {}
        for key in payload_modules.keys():
            kl = key.lower()
            if "/windows/" in kl: platforms["Windows"] = platforms.get("Windows", 0) + 1
            elif "/linux/" in kl: platforms["Linux"] = platforms.get("Linux", 0) + 1
            elif "/android/" in kl: platforms["Android"] = platforms.get("Android", 0) + 1
            elif "/mac" in kl or "/osx" in kl: platforms["macOS"] = platforms.get("macOS", 0) + 1
            else: platforms["Multi"] = platforms.get("Multi", 0) + 1
            if "reverse" in kl: payload_types["Reverse"] = payload_types.get("Reverse", 0) + 1
            elif "bind" in kl: payload_types["Bind"] = payload_types.get("Bind", 0) + 1
            elif "meterpreter" in kl: payload_types["Meterpreter"] = payload_types.get("Meterpreter", 0) + 1
            elif "shell" in kl: payload_types["Shell"] = payload_types.get("Shell", 0) + 1
        console.print(table)
        console.print(f"\n[bold]Payload Statistics:[/bold]")
        console.print(f"  • Total Payloads: [cyan]{total_payloads}[/cyan]")
        if payload_types:
            type_stats = " | ".join([f"{k}: {v}" for k, v in payload_types.items()])
            console.print(f"  • Types: {type_stats}")
        if platforms:
            platform_stats = " | ".join([f"{k}: {v}" for k, v in platforms.items()])
            console.print(f"  • Platforms: {platform_stats}")

    # === TAMPILAN SAMA PERSIS DENGAN FRAMEWORK1.PY ===
    def _show_modules_by_type(self, module_type):
        """Menampilkan modul berdasarkan type (recon, strike, hold, ops) dengan tampilan seperti Metasploit"""
        type_modules = {}
        type_lower = module_type.lower()
        
        for key, path in self.modules.items():
            if not key.startswith("modules/"): 
                continue
                
            meta = self.metadata.get(key, {})
            if not meta.get("options"):
                continue
            
            # Hanya 4 tipe tetap seperti framework1.py
            if f"/{type_lower}/" in key.lower():
                type_modules[key] = meta
        
        if not type_modules:
            console.print(f"No {module_type} modules found.", style="yellow")
            return
        
        type_descriptions = {
            'recon': 'Reconnaissance Modules',
            'strike': 'Strike/Exploitation Modules', 
            'hold': 'Hold/Persistence Modules',
            'ops': 'Operations Modules'
        }
        
        description = type_descriptions.get(module_type.lower(), f"{module_type.capitalize()} Modules")
        
        table = Table(
            title=f"{description}",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold white",
            title_style="bold white"
        )
        
        table.add_column("Name", style="green", width=40, overflow="fold")
        table.add_column("Category", style="yellow", width=30)
        table.add_column("Rank", style="red", width=30)
        table.add_column("Description", style="white", min_width=30)
        
        for key, meta in sorted(type_modules.items()):
            display_name = key[len("modules/"):]
            category = "general"
            parts = key.split('/')
            if len(parts) > 2:
                category = parts[2]
            
            rank = meta.get("rank", "normal")
            description = meta.get("description", "No description available")
            
            rank_color = {
                "excellent": "bold green",
                "great": "green", 
                "good": "yellow",
                "normal": "white",
                "average": "white",
                "low": "red",
                "manual": "bold red"
            }.get(rank.lower(), "white")
            
            table.add_row(
                display_name,
                category,
                f"[{rank_color}]{rank.capitalize()}[/{rank_color}]",
                description
            )
        
        console.print(table)
        console.print(f"\n[i]{len(type_modules)} modules[/i]")

    def _show_available_types(self):
        available_types = self._get_available_types()
        if not available_types:
            console.print("No module types found.", style="yellow")
            return
        
        table = Table(title="Available Module Types", box=box.SIMPLE_HEAVY)
        table.add_column("Type", style="bold cyan")
        table.add_column("Count", style="green")
        table.add_column("Description", style="white")
        
        type_descriptions = {
            'recon': 'Intelligence gathering & reconnaissance',
            'strike': 'Offensive operations & exploitation', 
            'hold': 'Position maintenance & persistence',
            'ops': 'Ongoing operations & payload execution'
        }
        
        for type_name, count in sorted(available_types.items()):
            desc = type_descriptions.get(type_name, 'No description')
            table.add_row(type_name.upper(), str(count), desc)
        
        console.print(table)
        console.print(f"\n[yellow]Usage: show {', '.join(available_types.keys())}[/yellow]")

    def _get_available_types(self):
        types_count = {
            'recon': 0,
            'strike': 0,
            'hold': 0,
            'ops': 0
        }
        
        for key in self.modules.keys():
            if not key.startswith("modules/"):
                continue
            if "/recon/" in key.lower():
                types_count['recon'] += 1
            if "/strike/" in key.lower():
                types_count['strike'] += 1
            if "/hold/" in key.lower():
                types_count['hold'] += 1
            if "/ops/" in key.lower():
                types_count['ops'] += 1
        
        return {k: v for k, v in types_count.items() if v > 0}

    def cmd_show(self, args):
        if not args:
            console.print("[bold red][!][/bold red] Argument Failed")
            console.print("[bold green][✓][/bold green] Valid parameters: show modules|recon|strike|hold|ops|payloads")
            return
        
        subcommand = args[0].lower()
        
        if subcommand == "modules":
            self._show_all_modules()
        elif subcommand == "payloads":
            self.cmd_payloads([])
        elif subcommand == "types":
            self._show_available_types()
        elif subcommand in ['recon', 'strike', 'hold', 'ops']:
            self._show_modules_by_type(subcommand)
        elif subcommand.startswith("modules/"):
            category = subcommand[8:]
            self._show_modules_by_category(category)
        else:
            console.print(f"Unknown show subcommand: {subcommand}", style="red")
            console.print("Usage: show modules|recon|strike|hold|ops|payloads", style="yellow")

    def _show_all_modules(self):
        terminal_width = shutil.get_terminal_size((80, 20)).columns
        MAX_MODULE_WIDTH = terminal_width // 4
        MAX_RANK_WIDTH = terminal_width // 6
        MAX_DESC_WIDTH = terminal_width // 4
        table = Table(box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("Module", style="bold white", width=MAX_MODULE_WIDTH, overflow="fold", justify="left")
        table.add_column("Rank", style="bold yellow", width=MAX_RANK_WIDTH, justify="center")
        table.add_column("Description", style="white", min_width=10, overflow="fold", justify="left")
        for k, v in sorted(self.metadata.items()):
            meta = self.metadata.get(k, {}) or {}
            if not meta.get("options"):
               continue
            display_key = k.replace("modules/", "", 1)
            if "__pycache__" in display_key:
                display_key = re.sub(r"\/__pycache__\/.*$", "", display_key)
                display_key = re.sub(r"(\.cpython-\d+)?$", "", display_key)
            if display_key.endswith('.py'):
                display_key = display_key[:-3]
            rank = meta.get("rank", "Normal")
            desc = v.get("description", "(no description)")
            table.add_row(display_key, rank, desc)
        panel = Panel(table, title="All Modules", border_style="white", expand=True)
        console.print(panel)

    def _show_modules_by_category(self, category):
        category_modules = {}
        for key, path in self.modules.items():
            meta = self.metadata.get(key, {})
            if not meta.get("options"):
               continue
            if not key.startswith("modules/"): continue
            if key.startswith(f"modules/{category}"):
                category_modules[key] = self.metadata.get(key, {})
        if not category_modules:
            console.print(f"No modules found in category: {category}", style="yellow")
            available_categories = self._get_available_categories()
            if available_categories:
                console.print("Available categories:", style="yellow")
                for cat in sorted(available_categories):
                    console.print(f"  • {cat}", style="dim")
            return
        table = Table(title=f"Modules in {category}", box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("Module", style="bold cyan", width=35)
        table.add_column("Type", style="yellow", width=15)
        table.add_column("Platform", style="green", width=12)
        table.add_column("Rank", style="red", width=8)
        table.add_column("Description", style="white", min_width=25)
        for key, meta in sorted(category_modules.items()):
            display_name = key[len("modules/"):]
            kl = key.lower()
            module_type = "unknown"
            if "exploit" in kl: module_type = "exploit"
            elif "scanner" in kl or "discovery" in kl: module_type = "scanner"
            elif "auxiliary" in kl: module_type = "auxiliary"
            elif "post" in kl: module_type = "post"
            elif "payload" in kl: module_type = "payload"
            elif "encoder" in kl: module_type = "encoder"
            platform_info = meta.get("platform", "multi")
            if isinstance(platform_info, str): platform_info = platform_info.capitalize()
            rank = meta.get("rank", "Normal")
            description = meta.get("description", "No description available")
            table.add_row(display_name, module_type, str(platform_info), str(rank), description)
        total_modules = len(category_modules)
        module_types = {}
        platforms = {}
        for key in category_modules.keys():
            kl = key.lower()
            if "/windows/" in kl: platforms["Windows"] = platforms.get("Windows", 0) + 1
            elif "/linux/" in kl: platforms["Linux"] = platforms.get("Linux", 0) + 1
            elif "/android/" in kl: platforms["Android"] = platforms.get("Android", 0) + 1
            elif "/mac" in kl or "/osx" in kl: platforms["macOS"] = platforms.get("macOS", 0) + 1
            else: platforms["Multi"] = platforms.get("Multi", 0) + 1
            if "exploit" in kl: module_types["Exploit"] = module_types.get("Exploit", 0) + 1
            elif "scanner" in kl or "discovery" in kl: module_types["Scanner"] = module_types.get("Scanner", 0) + 1
            elif "auxiliary" in kl: module_types["Auxiliary"] = module_types.get("Auxiliary", 0) + 1
            elif "payload" in kl: module_types["Payload"] = module_types.get("Payload", 0) + 1
        console.print(table)
        console.print(f"\n[bold]Category Statistics:[/bold]")
        console.print(f"  • Total Modules: [cyan]{total_modules}[/cyan]")
        if module_types:
            type_stats = " | ".join([f"{k}: {v}" for k, v in module_types.items()])
            console.print(f"  • Types: {type_stats}")
        if platforms:
            platform_stats = " | ".join([f"{k}: {v}" for k, v in platforms.items()])
            console.print(f"  • Platforms: {platform_stats}")

    def _get_available_categories(self):
        categories = set()
        for key in self.modules.keys():
            if key.startswith("modules/"):
                rel_path = key[8:]
                if '/' in rel_path:
                    category = rel_path.split('/')[0]
                    categories.add(category)
        return categories

    def cmd_info(self, args):
        if not self.loaded_module:
            console.print("No module loaded. Use 'use <module>' first.", style="red")
            return
        full_module_path = self.loaded_module.name
        path_parts = full_module_path.split('/')
        mod_type = "UNKNOWN"
        if len(path_parts) > 1:
            mod_type = path_parts[1].upper()
        mod = self.loaded_module.module
        meta = getattr(mod, "MODULE_INFO", {}) or {}
        name = meta.get("name", self.loaded_module.name.split('/')[-1])
        authors = meta.get("author", meta.get("authors", "Unknown"))
        description = meta.get("description", "No description provided.")
        license_ = meta.get("license", "Unknown")
        references = meta.get("references", [])
        dependencies = meta.get("dependencies", [])
        dep_status = {}
        if dependencies:
            dep_status = self._check_dependencies(dependencies)
        console.print(f"\n[bold white]       Name: [/bold white][bold cyan]{name}[/bold cyan]")
        console.print(f"[bold white]     Module: [/bold white]{self.loaded_module.name}")
        console.print(f"[bold white]       Type: [/bold white]{mod_type}")
        console.print(f"[bold white]   Platform: [/bold white]{meta.get('platform', 'All')}")
        console.print(f"[bold white]       Arch: [/bold white]{meta.get('arch', 'All')}")
        console.print(f"[bold white]     Author: [/bold white]{authors}")
        console.print(f"[bold white]    License: [/bold white]{license_}")
        console.print(f"[bold white]       Rank: [/bold white]{meta.get('rank', 'Normal')}")
        console.print(f"\n[bold white]Description:[/bold white]")
        desc_lines = textwrap.fill(description, width=80)
        console.print(Panel(desc_lines, border_style="blue", box=box.SQUARE))
        if dependencies:
            console.print(f"\n[bold white]Dependencies:[/bold white]")
            deps_table = Table(show_header=True, header_style="bold white", box=box.SIMPLE, show_edge=False)
            deps_table.add_column("Package", style="white", width=25)
            deps_table.add_column("Status", style="white", width=15)
            deps_table.add_column("Action", style="white", width=30)
            for dep in dependencies:
                status = dep_status.get(dep, False)
                status_text = "[green]Available[/green]" if status else "[red]Missing[/red]"
                action_text = "[green]Ready[/green]" if status else f"[yellow]pip install {dep}[/yellow]"
                deps_table.add_row(dep, status_text, action_text)
            console.print(deps_table)
        if references:
            console.print(f"\n[bold white]References:[/bold white]")
            for i, ref in enumerate(references, 1):
                console.print(f"  [bold white]{i}.[/bold white] {ref}")
        if hasattr(mod, "OPTIONS") and isinstance(getattr(mod, "OPTIONS"), dict):
            opts = self.loaded_module.get_options()
            if opts:
                console.print(f"\n[bold yellow]Module options ({self.loaded_module.name}):[/bold yellow]")
                console.print("")
                table = Table(show_header=True, header_style="bold yellow", box=box.SIMPLE, show_edge=False)
                table.add_column("Name", style="white", width=25, no_wrap=True)
                table.add_column("Current", style="cyan", width=25, no_wrap=True)
                table.add_column("Required", style="white", width=25, justify="center")
                table.add_column("Description", style="white", width=30)
                for name, info in opts.items():
                    current = str(info.get('value', '')).strip()
                    if not current: current = info.get('default', '')
                    if not current: current = ""
                    required = "yes" if info.get('required') else "no"
                    desc = info.get('description', 'No description')
                    table.add_row(name, current, required, desc)
                console.print(table)
            else:
                console.print(f"\n[bold yellow]This module has no options.[/bold yellow]")
        else:
            console.print(f"\n[bold yellow]This module has no options.[/bold yellow]")
        console.print("")

    def cmd_options(self, args):
        if not self.loaded_module:
            console.print("No module loaded.", style="red")
            return
        if hasattr(self.loaded_module.module, "OPTIONS"):
            table = Table(show_header=True, header_style="bold white", box=box.SIMPLE)
            table.add_column("Name", width=30, no_wrap=True)
            table.add_column("Current", justify="center", width=30)
            table.add_column("Required", justify="center", width=15)
            table.add_column("Description", width=50)
            for k, v in self.loaded_module.get_options().items():
                current_setting = str(v['value']) if 'value' in v else "Not Set"
                required = "Yes" if v.get('required') else "No"
                description = v.get('description', "No description available.")
                table.add_row(k, current_setting, required, description)
            panel = Panel(table, title="Module Options", border_style="white", expand=False)
            console.print(panel)
        else:
            console.print(f"Module '{self.loaded_module.name}' has no configurable options.", style="yellow")

    def cmd_set(self, args):
        if not self.loaded_module: 
            console.print("No module loaded.", style="red")
            return
        if len(args) < 2: 
            console.print("Usage: set <option> <value>", style="red")
            return
        opt, val = args[0], " ".join(args[1:])
        try:
            self.loaded_module.set_option(opt, val)
            console.print(f"{opt} => {val}", style="green")
        except Exception as e:
            console.print(str(e), style="red")

    def cmd_back(self, args):
        if self.loaded_module: 
            console.print(f"Unloaded {self.loaded_module.name}", style="yellow")
            self.loaded_module = None
        else: 
            console.print("No module loaded.", style="red")

    def cmd_scan(self, args):
        self.scan_modules()
        console.print(f"Scanned {len(self.modules)} modules.", style="green")

    def cmd_search(self, args):
        if not args:
            return console.print("Usage: search <keyword>", style="red")
        keyword = " ".join(args).strip().lower()
        results = []
        for key, meta in self.metadata.items():
            if keyword in key.lower() or keyword in meta.get("description","").lower():
                if meta.get("options"):
                    results.append((key, meta.get("description", "(no description)")))
        if not results:
            return console.print(f"No modules matching '{keyword}'", style="yellow")
        table = Table(box=box.SIMPLE)
        table.add_column("Module", style="bold red", overflow="fold")
        table.add_column("Description")
        for key, desc in sorted(results):
            display_key = key.replace("modules/", "", 1)
            table.add_row(display_key, desc or "(no description)")
        panel = Panel(table, title=f"Module for: {keyword}", border_style="white", expand=True)
        console.print(panel)

    def cmd_banner(self, args):
        console.print(get_random_banner())

    def cmd_cd(self, args):
        if not args: return
        try: 
            os.chdir(args[0])
            console.print("Changed Directory to: " + os.getcwd())
        except Exception as e: 
            console.print("Error: " + str(e), style="red")

    def cmd_pwd(self, args):
           try:
               console.print(f"[bold cyan]Current Directory:[/bold cyan] [white]{os.getcwd()}[/white]")
           except Exception as e:
               console.print(f"[red]Error:[/red] {e}", style="red")

    def cmd_ls(self, args):
        try:
            for f in os.listdir(): 
                console.print(f)
        except Exception as e: 
            console.print("Error: " + str(e), style="red")

    def cmd_clear(self, args): 
        os.system("cls" if platform.system().lower() == "windows" else "clear")

    def repl(self):
        console.print(
            "[bold cyan]=[ Lazy Framework v2.0 ]=[/]\n"
            "[dim]Advanced Penetration Testing Platform • Type 'help' for commands[/]\n"
        )
        #console.print("Lazy Framework - type 'help' for commands", style="bold cyan")
        console.print(get_random_banner()) 
        while True:
            try:
                if self.loaded_module:
                    full_path_without_prefix = self.loaded_module.name.replace("modules/", "", 1)
                    path_components = full_path_without_prefix.split('/')
                    category = path_components[0]
                    path_in_parentheses = '/'.join(path_components[1:])
                    colored_category = f"\x1b[34m{category}\x1b[0m"
                    colored_path_segment = f"(\x1b[41m\x1b[97m{path_in_parentheses}\x1b[0m)"
                    prompt = f"lzf {colored_category}{colored_path_segment} > "
                else:
                    prompt = "lzf > "
                line = input(prompt)
            except (EOFError, KeyboardInterrupt):
                break
            if not line.strip(): continue
            parts = shlex.split(line)
            cmd, args = parts[0], parts[1:]
            if cmd in ("exit", "quit"): 
                break
            getattr(self, f"cmd_{cmd}", lambda a: console.print("Unknown command", style="red"))(args)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
       from gui import run_gui
       run_gui()
    else:
       LazyFramework().repl()
