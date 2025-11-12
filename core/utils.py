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

console = Console()

BASE_DIR = Path(__file__).parent
MODULE_DIR, EXAMPLES_DIR, BANNER_DIR = BASE_DIR / "modules", BASE_DIR / "examples", BASE_DIR / "banner"
METADATA_READ_LINES = 120
_loaded_banners = []

# ========== Banner Loader ==========
def load_banners_from_folder():
    global _loaded_banners
    _loaded_banners = []
    BANNER_DIR.mkdir(parents=True, exist_ok=True)
    for p in sorted(BANNER_DIR.glob("*.txt")):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore").rstrip()
            if text:
                _loaded_banners.append(text + "\n\n")
        except Exception:
            pass
    if not _loaded_banners:
        _loaded_banners = ["\n"]

def colorize_banner(text):
    colors = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']
    color = random.choice(colors)
    return f"[{color}]{text}[/{color}]"

def get_random_banner():
    if not _loaded_banners:
        load_banners_from_folder()
    banner = random.choice(_loaded_banners).rstrip("\n")
    try:
        cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        cols = 80
    lines = banner.splitlines()
    max_len = max((len(line) for line in lines), default=0)
    scale = min(1.0, cols / max_len) if max_len > 0 else 1.0
    new_lines = [line[:int(cols)] for line in lines] if scale < 1.0 else [line.center(cols) for line in lines]
    return colorize_banner("\n".join(new_lines)) + "\n\n"


# ========== Animation: Tunggu Timeout → Hapus 100% (TANPA \n) ==========
class SingleLineMarquee:
    def __init__(self, 
                 text="[*] Starting the Lazy Framework Console...", 
                 text_speed: float = 6.06, 
                 spinner_speed: float = 0.06,
                 reset_delay: float = 0.01,
                 max_loops: int = 1,
                 clear_delay: float = 0.8):  # Tunggu sebelum hapus
        
        self.text = text
        self.spinner = itertools.cycle(['|', '/', '-', '\\'])
        self.alt_text = ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(text))
        
        self.text_speed = max(0.01, text_speed)
        self.spinner_speed = max(0.01, spinner_speed)
        self.reset_delay = max(0.0, reset_delay)
        self.clear_delay = max(0.0, clear_delay)  # Tunggu sebelum hapus
        
        self.max_loops = max_loops
        self.current_loop = 0
        
        self._stop = threading.Event()
        self._pos = 0
        self._thread = None

    def _compose(self, pos, spin):
        return f"{self.alt_text[:pos] + self.text[pos:]} [{spin}]"

    def _run(self):
        L = len(self.text)
        last_time = time.time()
        max_written = L

        while not self._stop.is_set():
            spin = next(self.spinner)
            now = time.time()
            
            if self._pos < L:
                if (now - last_time) >= self.text_speed:
                    self._pos += 1
                    last_time = now
                current = self._compose(self._pos, spin)
                max_written = max(max_written, len(current))
                sys.stdout.write('\r' + current)
                sys.stdout.flush()
                time.sleep(self.spinner_speed)
            
            else:
                if self._pos == L:
                    self.current_loop += 1
                
                sys.stdout.write('\r' + self.text + '   ')
                sys.stdout.flush()

                if self.current_loop >= self.max_loops:
                    break
                
                if self.reset_delay > 0.0:
                    time.sleep(self.reset_delay)
                    self._pos = 0
                    last_time = time.time()
                else:
                    break

        # === TUNGGU TIMEOUT → HAPUS 100% (TANPA \n) ===
        if not self._stop.is_set():
            time.sleep(self.clear_delay)  # Tunggu X detik
            erase_len = max_written + 20  # Margin besar → PASTI bersih
            sys.stdout.write('\r' + ' ' * erase_len + '\r')  # Hapus + kursor ke awal
            sys.stdout.flush()

    def start(self):
        if not (self._thread and self._thread.is_alive()):
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            
    def wait(self):
        if self._thread:
            self._thread.join()
            
    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join()


# ========== Search Class ==========
class Search:
    def __init__(self, modules, metadata):
        self.modules = modules
        self.metadata = metadata

    def search_modules(self, keyword):
        keyword = keyword.lower()
        results = []
        for key, meta in self.metadata.items():
            if keyword in key.lower() or keyword in meta.get("description", "").lower():
                results.append((key, meta.get("description", "(no description)")))
        return results
