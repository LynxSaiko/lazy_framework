#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import io
import re
import subprocess
import threading
from contextlib import redirect_stdout, redirect_stderr
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread, QTimer, QUrl
from PyQt6.QtGui import QFont, QTextCursor, QPalette, QColor, QAction, QKeySequence, QIntValidator
from PyQt6.QtCore import QSize
from PyQt6.QtGui import QIcon
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtNetwork import QNetworkProxy
# Import LazyFramework
from bin.console import LazyFramework

# === UNIVERSAL OUTPUT CAPTURE ===
class UniversalCapture(QObject):
    output_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.original_print = __builtins__['print']

    def start_capture(self):
        """Start capturing all output"""
        sys.stdout = self
        sys.stderr = self
        __builtins__['print'] = self.print_capture

    def stop_capture(self):
        """Stop capturing"""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        __builtins__['print'] = self.original_print

    def write(self, text):
        """Capture stdout/stderr"""
        if text and text.strip():
            self.output_signal.emit(str(text))

    def flush(self):
        pass

    def print_capture(self, *args, **kwargs):
        """Capture print statements"""
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        text = sep.join(str(arg) for arg in args) + end
        self.output_signal.emit(text)

# === PATCHED SUBPROCESS ===
class PatchedPopen(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        self.output_callback = kwargs.pop('output_callback', None)

        # Force capture output
        kwargs['stdout'] = subprocess.PIPE
        kwargs['stderr'] = subprocess.STDOUT
        kwargs['universal_newlines'] = True
        kwargs['bufsize'] = 1

        super().__init__(*args, **kwargs)

        if self.output_callback and self.stdout:
            self.output_thread = threading.Thread(target=self._read_output)
            self.output_thread.daemon = True
            self.output_thread.start()

    def _read_output(self):
        """Read output in real-time"""
        try:
            for line in iter(self.stdout.readline, ''):
                if line and self.output_callback:
                    self.output_callback(line.rstrip())
        except Exception:
            pass

# === MODULE RUNNER WITH SUBPROCESS PATCHING ===
class ModuleRunner(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, framework, module_instance):
        super().__init__()
        self.framework = framework
        self.module_instance = module_instance
        self.capture = UniversalCapture()
        self.capture.output_signal.connect(self.output.emit)

        # Backup original functions
        self.original_popen = subprocess.Popen
        self.original_system = os.system

    def run(self):
        try:
            # Apply patches before capture
            self._apply_patches()

            # Start capturing ALL output
            self.capture.start_capture()

            # Run the module
            self.module_instance.run(self.framework.session)

        except Exception as e:
            self.output.emit(f"Module Error: {e}")
        finally:
            # Restore everything
            self._restore_patches()
            self.capture.stop_capture()
            self.finished.emit()

    def _apply_patches(self):
        """Apply all necessary patches"""
        # Patch subprocess.Popen
        subprocess.Popen = self._patched_popen

        # Patch os.system
        os.system = self._patched_system

    def _restore_patches(self):
        """Restore original functions"""
        subprocess.Popen = self.original_popen
        os.system = self.original_system

    def _patched_popen(self, *args, **kwargs):
        """Patched subprocess.Popen"""
        kwargs['output_callback'] = self.output.emit
        return PatchedPopen(*args, **kwargs)

    def _patched_system(self, command):
        """Patched os.system"""
        try:
            self.output.emit(f"$ {command}")

            process = PatchedPopen(
                command,
                shell=True,
                output_callback=self.output.emit
            )

            process.wait()
            return process.returncode
        except Exception as e:
            self.output.emit(f"Command error: {e}")
            return -1

# === RICH CONSOLE FOR GUI ===
class GUIConsole:
    def __init__(self, output_callback):
        self.output_callback = output_callback

    def print(self, *args, **kwargs):
        """Print dengan rich formatting ke GUI"""
        try:
            from io import StringIO
            from rich.console import Console

            with StringIO() as buffer:
                console = Console(file=buffer, force_terminal=False, width=120)
                console.print(*args, **kwargs)
                output = buffer.getvalue()
                if output.strip():
                    # Clean ANSI sequences
                    #clean_output = re.sub(r'\x1b\[[0-9;]*[mG]', '', output)
                    self.output_callback(output)
        except Exception as e:
            self.output_callback(f"Console error: {e}")

# === PROXY SETTINGS DIALOG - TANPA BROWSE FILE ===
class ProxySettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("Proxy Settings")
        self.setModal(True)
        self.setFixedSize(400, 300)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # HAPUS BAGIAN PROXY LIST DARI FILE
        # Langsung ke Manual Proxy Input saja

        # Manual Proxy Input (sederhana)
        manual_group = QGroupBox("Manual Proxy Configuration")
        manual_layout = QFormLayout()
        
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("127.0.0.1 or proxy.com")
        manual_layout.addRow("Host:", self.host_input)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("8080")
        self.port_input.setValidator(QIntValidator(1, 65535))
        manual_layout.addRow("Port:", self.port_input)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["HTTP", "SOCKS5", "SOCKS4"])
        manual_layout.addRow("Type:", self.type_combo)
        
        manual_group.setLayout(manual_layout)
        layout.addWidget(manual_group)

        # Quick Tor button
        tor_group = QGroupBox("Quick Setup")
        tor_layout = QHBoxLayout()
        
        tor_btn = QPushButton("Use Tor Proxy (127.0.0.1:9050)")
        tor_btn.clicked.connect(self.set_tor_proxy)
        tor_layout.addWidget(tor_btn)
        
        tor_group.setLayout(tor_layout)
        layout.addWidget(tor_group)

        # Action Buttons
        btn_layout = QHBoxLayout()
        
        test_btn = QPushButton("Test")
        test_btn.clicked.connect(self.test_proxy)
        btn_layout.addWidget(test_btn)
        
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_proxy)
        apply_btn.setDefault(True)
        btn_layout.addWidget(apply_btn)
        
        disable_btn = QPushButton("Disable")
        disable_btn.clicked.connect(self.disable_proxy)
        btn_layout.addWidget(disable_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.load_current_settings()

    def set_tor_proxy(self):
        """Set Tor proxy settings"""
        self.host_input.setText("127.0.0.1")
        self.port_input.setText("9050")
        self.type_combo.setCurrentText("SOCKS5")

    def load_current_settings(self):
        """Load current proxy settings"""
        if self.parent.current_proxy:
            self.host_input.setText(self.parent.current_proxy.get('server', ''))
            self.port_input.setText(str(self.parent.current_proxy.get('port', '')))
            self.type_combo.setCurrentText(self.parent.current_proxy.get('type', 'HTTP').upper())

    def test_proxy(self):
        """Test proxy connection"""
        proxy_config = self.get_proxy_config()
        if proxy_config:
            self.parent.test_proxy_connection(proxy_config)

    def apply_proxy(self):
        """Apply proxy settings"""
        proxy_config = self.get_proxy_config()
        if proxy_config:
            # Tentukan proxy mode berdasarkan type
            if proxy_config['type'] == 'socks5' and proxy_config['server'] == '127.0.0.1' and proxy_config['port'] == 9050:
                self.parent.framework.session["proxy_mode"] = "Tor"
            else:
                self.parent.framework.session["proxy_mode"] = "Manual"
            
            self.parent.set_proxy(proxy_config)
            self.parent.enable_proxy()
            self.accept()

    def disable_proxy(self):
        """Disable proxy"""
        self.parent.disable_proxy()
        self.accept()

    def get_proxy_config(self):
        """Get proxy configuration from inputs"""
        host = self.host_input.text().strip()
        port = self.port_input.text().strip()
        proxy_type = self.type_combo.currentText().lower()

        if not host or not port:
            QMessageBox.warning(self, "Error", "Please enter host and port")
            return None

        try:
            port_int = int(port)
        except ValueError:
            QMessageBox.warning(self, "Error", "Please enter a valid port number")
            return None

        return {
            'type': proxy_type,
            'server': host,
            'port': port_int,
            'username': '',
            'password': ''
        }

# === MAIN GUI COMPLETE ===
class LazyFrameworkGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(""))
        self.framework = LazyFramework()
        self.capture = UniversalCapture()
        self.capture.output_signal.connect(self.append_output)

        # Replace framework console dengan GUI console
        self.framework.console = GUIConsole(self.append_output)

        self.current_module = None
        self.workers = []
        self.command_history = []
        self.history_index = -1
        self.module_runner = None
        self.current_proxy = None
        self.proxy_enabled = False
        
        self.custom_proxies = []        # semua proxy dari proxies.txt
        self.current_proxy_index = -1

        self.browser = None
        self.browser_tab = None
        self.browser_controls_widget = None
        self.browser_placeholder = None
        
        self.init_ui()
        self.start_global_capture()

        import glob
        import shutil
        cache_dirs = glob.glob("**/__pycache__", recursive=True)
        for cache in cache_dirs:
            try:
                shutil.rmtree(cache)
            except Exception as e:
                pass
                
        self.load_banner()
        QTimer.singleShot(2000, self.start_tor_auto_rotate)
        self.last_tor_ip = None
       
    def init_ui(self):
        self.setWindowTitle("LazyFramework GUI")
        self.setGeometry(100, 50, 1800, 1000)
        
         # Apply saved font (if any)
        saved_font = self.framework.session.get('font', 'Roboto Mono Bold')
        saved_size = self.framework.session.get('font_size', 12)
        default_font = QFont(saved_font, saved_size)
        self.setFont(default_font)
        # Set dark theme
        self.set_dark_theme()

        # Create menu bar
        self.create_menu_bar()

        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        # === LEFT SIDEBAR ===
        left_sidebar = self.create_left_sidebar()
        layout.addWidget(left_sidebar, 1)

        # === MAIN CONTENT AREA ===
        main_content = self.create_main_content()
        layout.addWidget(main_content, 3)

        # === RIGHT SIDEBAR ===
        right_sidebar = self.create_right_sidebar()
        layout.addWidget(right_sidebar, 1)

        # Load initial modules
        QTimer.singleShot(100, self.load_all_modules)

    def start_global_capture(self):
        """Start global output capture"""
        self.capture.start_capture()

    def set_dark_theme(self):
        """Set dark theme for the application"""
        self.setStyleSheet("""
            QMainWindow {
                background: #1e1e1e;
                color: #d4d4d4;
            }
            QWidget {
                background: #1e1e1e;
                color: #d4d4d4;
            }
            QPushButton {
                background: #2d2d2d;
                color: #ffffff;
                border: 1px solid #404040;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #3d3d3d;
                border: 1px solid #505050;
            }
            QPushButton:pressed {
                background: #1d1d1d;
            }
            QPushButton:disabled {
                background: #252525;
                color: #666666;
            }
            QLineEdit {
                background: #252525;
                color: #ffffff;
                border: 1px solid #404040;
                padding: 8px;
                border-radius: 4px;
                selection-background-color: #0078d4;
            }
            QLineEdit:focus {
                border: 1px solid #0078d4;
            }
            QTextEdit {
                background: #030305;
                color: #d4d4d4;
                border: 1px solid #404040;
                border-radius: 4px;
                font-family: 'Roboto Mono';
            }
            QListWidget, QTableWidget {
                background: #252525;
                color: #d4d4d4;
                border: 1px solid #404040;
                border-radius: 4px;
                outline: none;
            }
            QListWidget::item:selected, QTableWidget::item:selected {
                background: #0078d4;
                color: white;
            }
            QListWidget::item:hover, QTableWidget::item:hover {
                background: #2a2a2a;
            }
            QHeaderView::section {
                background: #2d2d2d;
                color: #d4d4d4;
                padding: 6px;
                border: none;
                font-weight: normal;
            }
            QTabWidget::pane {
                border: 1px solid #404040;
                background: #252525;
                font-size: 18px;
            }
            QTabBar::tab {
                background: #2d2d2d;
                color: #d4d4d4;
                font-size: 13px;
                padding: 8px 16px;
                border: 1px solid #404040;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #0078d4;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background: #3d3d3d;
            }
            QGroupBox {
                font-weight: normal;
                color: #00ff00;
                border: 1px solid #404040;
                margin-top: 10px;
                padding-top: 10px;
                border-radius: 4px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                background: #1e1e1e;
            }
            QLabel {
                color: #d4d4d4;
            }
            QProgressBar {
                border: 1px solid #404040;
                border-radius: 4px;
                background: #252525;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background: #0078d4;
                border-radius: 3px;
            }
            QComboBox {
                background: #252525;
                color: #ffffff;
                border: 1px solid #404040;
                padding: 6px;
                border-radius: 4px;
            }
            QComboBox:hover {
                border: 1px solid #505050;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #252525;
                color: #ffffff;
                border: 1px solid #404040;
                selection-background-color: #0078d4;
            }
            QWebEngineView {
                border: 1px solid #404040;
                border-radius: 4px;
            }
        """)

    def auto_rotate_proxy(self):
        mode = self.framework.session.get("proxy_mode", "Disabled")

        if mode == "Tor":
            self.rotate_tor_ip()

        elif mode == "FileProxy":
            self.rotate_custom_proxy()

    def rotate_custom_proxy(self):
        if not self.custom_proxies:
            self.append_output("[yellow]No custom proxies loaded[/]")
            return

        # next proxy
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.custom_proxies)
        self.current_proxy = self.custom_proxies[self.current_proxy_index]
        p = self.current_proxy

        self.append_output(f"[cyan]Switched to proxy → {p['server']}:{p['port']} ({p['type']})[/]")
        
        self.append_output(f"[cyan]Browser proxy updated via PAC → {p['server']}:{p['port']}[/]")
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu('File')

        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View menu
        view_menu = menubar.addMenu('View')

        refresh_action = QAction('Refresh Modules', self)
        refresh_action.setShortcut('F5')
        refresh_action.triggered.connect(self.refresh_modules)
        view_menu.addAction(refresh_action)

        # Tools menu
        tools_menu = menubar.addMenu('Tools')

        clear_action = QAction('Clear Console', self)
        clear_action.setShortcut('Ctrl+L')
        clear_action.triggered.connect(self.clear_console)
        tools_menu.addAction(clear_action)

         # Settings menu
        settings_menu = menubar.addMenu('Settings')
        font_action = QAction('Change Font', self)
        font_action.triggered.connect(self.change_font)
        settings_menu.addAction(font_action)

        # Proxy menu
        proxy_menu = menubar.addMenu('Proxy')
    
        proxy_settings = QAction('Proxy Settings', self)
        proxy_settings.setShortcut('Ctrl+P')
        proxy_settings.triggered.connect(self.show_proxy_settings)
        proxy_menu.addAction(proxy_settings)
        
        proxy_menu.addSeparator()
        
        enable_proxy = QAction('Enable Proxy', self)
        enable_proxy.setShortcut('Ctrl+Shift+P')
        enable_proxy.triggered.connect(self.enable_proxy)
        proxy_menu.addAction(enable_proxy)
        
        disable_proxy = QAction('Disable Proxy', self)
        disable_proxy.triggered.connect(self.disable_proxy)
        proxy_menu.addAction(disable_proxy)
        
        test_proxy = QAction('Test Proxy', self)
        test_proxy.triggered.connect(self.test_proxy_connection)
        proxy_menu.addAction(test_proxy)

    def create_main_content(self):
        """Create main content area"""
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)

        # Tab widget for different views
        self.tabs = QTabWidget()

        # Console tab
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("DejaVu Sans Mono Bold", 9))
        self.console_output.setAcceptRichText(True)
        self.tabs.addTab(self.console_output, "Console")

        # Options tab
        self.options_widget = QWidget()
        self.options_layout = QFormLayout(self.options_widget)
        self.options_scroll = QScrollArea()
        self.options_scroll.setWidgetResizable(True)
        self.options_scroll.setWidget(self.options_widget)
        self.tabs.addTab(self.options_scroll, "Options")

        # Module info tab
        self.module_detail_info = QTextEdit()
        self.module_detail_info.setReadOnly(True)
        self.module_detail_info.setFont(QFont("Hack", 11))
        self.tabs.addTab(self.module_detail_info, "Module Info")

        layout.addWidget(self.tabs)

        # Control buttons
        control_layout = QHBoxLayout()

        self.run_btn = QPushButton("START")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: #0e0e0f; 
                color: white; 
                font-weight: normal; 
                font-size: 14px; 
                padding: 12px;
                border-radius: 6px;
                outline: none;
            }
            QPushButton:hover {
                background: #072ff5;
            }
            QPushButton:disabled {
                background: #072ff5;
                color: #888888;
            }
        """)
        self.run_btn.clicked.connect(self.run_module)
        self.run_btn.setEnabled(False)
        control_layout.addWidget(self.run_btn)

        self.back_btn = QPushButton("BACK")
        self.back_btn.clicked.connect(self.unload_module)
        self.back_btn.setEnabled(False)
        control_layout.addWidget(self.back_btn)

        clear_btn = QPushButton("Clear Console")
        clear_btn.clicked.connect(self.clear_console)
        control_layout.addWidget(clear_btn)

        layout.addLayout(control_layout)

        return main_widget

    def create_right_sidebar(self):
        """Create right sidebar with session info and quick actions"""
        sidebar = QWidget()
        sidebar.setMaximumWidth(380)
        layout = QVBoxLayout(sidebar)

        # Session info
        session_group = QGroupBox("Session Info")
        session_group.setStyleSheet("""
            QGroupBox {
                font-weight: normal;
                color: #ffffff;
                border: 1px solid #404040;
                margin-top: 10px;
                padding-top: 10px;
                border-radius: 4px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                background: #1e1e1e;
                color: #ffffff;
            }
        """)
        session_layout = QVBoxLayout()

        self.session_info = QTextEdit()
        self.session_info.setMaximumHeight(120)
        self.session_info.setReadOnly(True)
        self.session_info.setFont(QFont("Hack", 10))
        self.session_info.setStyleSheet("color: #ffffff; background-color: #252525;")
        session_layout.addWidget(self.session_info)

        session_group.setLayout(session_layout)
        layout.addWidget(session_group)

        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_group.setStyleSheet("""
            QGroupBox {
                font-weight: normal;
                color: #ffffff;
                border: 1px solid #404040;
                margin-top: 10px;
                padding-top: 10px;
                border-radius: 4px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                background: #1e1e1e;
                color: #ffffff;
            }
        """)
        actions_layout = QVBoxLayout()

        quick_actions = [
            ("Show Modules", "show modules"),
            ("Show Options", "options"),
            ("Module Info", "info"),
            ("Scan Modules", "scan"),
            ("Show Banner", "banner")
        ]

        for action_name, command in quick_actions:
            btn = QPushButton(action_name)
            btn.clicked.connect(
                lambda checked, cmd=command: self.quick_command(cmd))
            actions_layout.addWidget(btn)

        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)

        # Current module status
        status_group = QGroupBox("Current Module")
        status_layout = QVBoxLayout()

        self.current_module_label = QLabel("No module loaded")
        self.current_module_label.setStyleSheet(
            "color: #ff5555; font-weight: bold;")
        status_layout.addWidget(self.current_module_label)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        # Spacer
        layout.addStretch()

        return sidebar

    # === BROWSER METHODS - MODIFIED (HIDE/SHOW) ===
    def navigate_to_url(self):
        """Navigate to URL from url bar"""
        if not hasattr(self, 'url_bar') or not self.url_bar:
            return
            
        url = self.url_bar.text().strip()
        if not url:
            return
            
        # Jika sudah lengkap dengan protocol
        if url.startswith(('http://', 'https://', 'file://')):
            self.browser.setUrl(QUrl(url))
            return
            
        # Coba tambahkan https:// jika seperti domain
        if '.' in url and ' ' not in url:
            self.browser.setUrl(QUrl('https://' + url))
        else:
            # Jika tidak, anggap sebagai pencarian
            self.browser.setUrl(QUrl(f'https://www.google.com/search?q={url.replace(" ", "+")}'))

    def create_left_sidebar(self):
        """Create left sidebar with modules and categories"""
        sidebar = QWidget()
        sidebar.setMaximumWidth(400)
        layout = QVBoxLayout(sidebar)

        # Search box
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search modules...")
        self.search_input.textChanged.connect(self.search_modules)
        search_layout.addWidget(self.search_input)

        search_btn = QPushButton("🔍")
        search_btn.setFixedWidth(40)
        search_btn.clicked.connect(self.perform_search)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)

        # Category buttons
        categories_layout = QHBoxLayout()
        categories = [
            ("All", "all"), ("Recon", "recon"), ("Strike", "strike"),
            ("Hold", "hold"), ("Ops", "ops"), ("Payloads", "payloads")
        ]

        for name, cat_type in categories:
            btn = QPushButton(name)
            btn.setProperty('category', cat_type)
            btn.clicked.connect(self.on_category_click)
            categories_layout.addWidget(btn)

        layout.addLayout(categories_layout)

        # Module list
        self.module_list = QListWidget()
        self.module_list.itemDoubleClicked.connect(self.load_selected_module)
        layout.addWidget(self.module_list)

        # Info Group dengan Browser Controls
        info_group = QGroupBox()
        info_layout = QVBoxLayout(info_group)

        # Tab widget untuk info dan browser
        self.info_browser_tabs = QTabWidget()

        # Tab 1: Module Info
        module_info_tab = QWidget()
        module_info_layout = QVBoxLayout(module_info_tab)
        module_info_layout.setContentsMargins(0, 0, 0, 0)

        self.module_info = QTextEdit()
        self.module_info.setReadOnly(True)

        self.module_info.setHtml("""
        <html>
        <head>
        <style>
            body { 
                background: #1e1e1e; 
                color: #d4d4d4; 
                font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
                padding: 20px;
                line-height: 1.6;
                font-size: 14px;
            }
            h2 { 
                color: #50fa7b; 
                font-size: 24px; 
                font-weight: 600;
                margin-bottom: 20px;
                border-bottom: 2px solid #50fa7b;
                padding-bottom: 10px;
            }
            h3 { 
                color: #8be9fd; 
                font-size: 18px; 
                font-weight: 600;
                margin: 25px 0 15px 0;
            }
            .card {
                background: #252525; 
                padding: 20px; 
                border-radius: 8px; 
                margin: 15px 0;
                border-left: 4px solid #6272a4;
                box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            }
            .tip-card {
                background: #1e2e1e; 
                border-left: 4px solid #50fa7b;
            }
            ul {
                margin: 10px 0;
                padding-left: 20px;
            }
            li {
                margin: 8px 0;
                padding-left: 5px;
            }
            b {
                color: #ffb86c;
                font-weight: 600;
            }
            .category {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 4px;
                font-weight: 600;
                font-size: 12px;
                margin-right: 8px;
            }
            .recon { background: #1e3a5c; color: #8be9fd; }
            .strike { background: #5c1e1e; color: #ff5555; }
            .hold { background: #5c4c1e; color: #f1fa8c; }
            .ops { background: #1e5c2e; color: #50fa7b; }
            .payloads { background: #3e1e5c; color: #bd93f9; }
        </style>
        </head>
        <body>

        <h2>LazyFramework GUI</h2>

        <div class="card">
            <h3>🚀 Quick Start Guide</h3>
            <ul>
                <li><b>Browse Modules:</b> Select from the list on the left</li>
                <li><b>Load Module:</b> Double-click the desired module</li>
                <li><b>Configure:</b> Set parameters in the "Options" tab</li>
                <li><b>Execute:</b> Click "START" to run the module</li>
                <li><b>Results:</b> View output in the "Console" tab</li>
            </ul>
        </div>

        <div class="card">
            <h3>🎯 Module Categories</h3>
            <ul>
                <li><span class="category recon">RECON</span> Information gathering & enumeration</li>
                <li><span class="category strike">STRIKE</span> Vulnerability assessment & exploitation</li>
                <li><span class="category hold">HOLD</span> Post-exploitation & persistence</li>
                <li><span class="category ops">OPS</span> Operational security & anti-forensics</li>
                <li><span class="category payloads">PAYLOADS</span> Payload generation & delivery</li>
            </ul>
        </div>

        <div class="card tip-card">
            <h3>💡 Professional Tips</h3>
            <ul>
                <li>Use proxy settings for enhanced anonymity during scans</li>
                <li>Save session configurations for different projects</li>
                <li>Always verify module options before execution</li>
                <li>Monitor system resources during large-scale operations</li>
                <li>Utilize the integrated browser for manual testing</li>
            </ul>
        </div>

        <div class="card">
            <h3>🔧 Key Features</h3>
            <ul>
                <li><b>Real-time Output:</b> Live console output with syntax highlighting</li>
                <li><b>Integrated Browser:</b> Built-in web browser for manual testing</li>
                <li><b>Proxy Support:</b> Full proxy configuration with auto-rotation</li>
                <li><b>Session Management:</b> Save and restore your work sessions</li>
                <li><b>Module Library:</b> Extensive collection of security tools</li>
            </ul>
        </div>

        </body>
        </html>
        """)


        module_info_layout.addWidget(self.module_info)

        self.info_browser_tabs.addTab(module_info_tab, "Module Info")

        # Tab 2: Browser - MODIFIED STRUCTURE
        browser_tab = QWidget()
        browser_tab_layout = QVBoxLayout(browser_tab)
        browser_tab_layout.setContentsMargins(0, 0, 0, 0)
        browser_tab_layout.setSpacing(5)

        # Browser control buttons
        browser_control_layout = QHBoxLayout()
        
        self.open_browser_btn = QPushButton("🌐 Open Browser")
        self.open_browser_btn.clicked.connect(self.open_browser_panel)
        self.open_browser_btn.setFixedSize(120, 30)
        self.open_browser_btn.setStyleSheet("""
            QPushButton {
                background: #1e1e1e;
                color: white;
                font-weight: bold;
                padding: 5px;
                border-radius: 3px;
                font-size: 10px;
            }
            QPushButton:hover {
                background: #42a5f5;
            }
        """)

        self.close_browser_btn = QPushButton("❌ Hide Browser")
        self.close_browser_btn.clicked.connect(self.close_browser_panel)
        self.close_browser_btn.setFixedSize(120, 30)
        self.close_browser_btn.setStyleSheet("""
            QPushButton {
                background: #1e1e1e;
                color: white;
                font-weight: bold;
                padding: 5px;
                border-radius: 3px;
                font-size: 10px;
            }
            QPushButton:hover {
                background: #ef5350;
            }
        """)
        self.close_browser_btn.setEnabled(False)

        browser_control_layout.addWidget(self.open_browser_btn)
        browser_control_layout.addWidget(self.close_browser_btn)
        browser_control_layout.addStretch()

        # Placeholder untuk browser (default state)
        self.browser_placeholder = QLabel("Browser is closed. Click 'Open Browser' to start.")
        self.browser_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.browser_placeholder.setStyleSheet("color: #666; font-style: italic; padding: 40px;")
        self.browser_placeholder.setMinimumHeight(200)

        browser_tab_layout.addLayout(browser_control_layout)
        browser_tab_layout.addWidget(self.browser_placeholder)

        self.info_browser_tabs.addTab(browser_tab, "Browser")

        # Tambahkan tab widget ke layout utama info group
        info_layout.addWidget(self.info_browser_tabs)
        layout.addWidget(info_group)

        return sidebar
    
    
    
    # === BROWSER PANEL METHODS - HIDE/SHOW VERSION ===
    def open_browser_panel(self):
        """Show the browser panel (jika sudah ada) atau buat baru"""
        if self.browser:
            # Browser sudah ada, cukup tampilkan
            self.browser_controls_widget.show()
            self.browser.show()
            self.browser_placeholder.hide()
            self.append_output("[dim]Browser panel shown[/]")
            self.update_browser_buttons()
            return
            
        # Create Browser Control Widgets
        self.browser_controls_widget = QWidget()
        control_layout = QHBoxLayout(self.browser_controls_widget)
        control_layout.setContentsMargins(0, 0, 0, 0)
        
        self.back_browser_btn = QPushButton("⬅")
        self.back_browser_btn.setFixedSize(30, 30)
        self.back_browser_btn.clicked.connect(self.browser_back)
        
        self.forward_browser_btn = QPushButton("⮕")
        self.forward_browser_btn.setFixedSize(30, 30)
        self.forward_browser_btn.clicked.connect(self.browser_forward)
        
        self.refresh_browser_btn = QPushButton("↻")
        self.refresh_browser_btn.setFixedSize(30, 30)
        self.refresh_browser_btn.clicked.connect(self.browser_refresh)

        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL or search...")
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        
        control_layout.addWidget(self.back_browser_btn)
        control_layout.addWidget(self.forward_browser_btn)
        control_layout.addWidget(self.refresh_browser_btn)
        control_layout.addWidget(self.url_bar)
        
        # Create WebEngineView
        self.browser = QWebEngineView()
        self.browser.settings().setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        self.browser.settings().setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        self.browser.urlChanged.connect(self.update_url_bar)
        self.browser.loadStarted.connect(self.on_load_started)
        self.browser.loadFinished.connect(self.on_load_finished)
        self.browser.setUrl(QUrl("https://www.google.com"))

        # Add to the browser tab layout
        browser_tab = self.info_browser_tabs.widget(1)
        browser_tab_layout = browser_tab.layout()
        
        # Remove placeholder dan tambahkan browser components
        self.browser_placeholder.hide()
        browser_tab_layout.insertWidget(1, self.browser_controls_widget)
        browser_tab_layout.insertWidget(2, self.browser)

        self.browser_tab = browser_tab
        self.append_output("[bold green]🌐 Browser Panel Opened[/]")
        self.update_browser_buttons()
        
        # Apply proxy settings if enabled
        if self.proxy_enabled and self.current_proxy:
            self.set_proxy(self.current_proxy)

    def close_browser_panel(self):
        """Hide the browser panel instead of closing it"""
        if not self.browser:
            self.append_output("[dim]Browser is already hidden[/]")
            return

        try:
            # Hentikan loading
            self.browser.stop()
            
            # Sembunyikan browser dan controls
            self.browser.hide()
            self.browser_controls_widget.hide()
            
            # Tampilkan placeholder
            self.browser_placeholder.show()
            
            self.append_output("[dim]Browser panel hidden[/]")
            self.update_browser_buttons()
            
        except Exception as e:
            self.append_output(f"[red]Error hiding browser: {e}[/]")

    def update_browser_buttons(self):
        """Update browser button states based on visibility"""
        if hasattr(self, 'browser') and self.browser:
            is_visible = self.browser.isVisible()
            self.open_browser_btn.setEnabled(not is_visible)
            self.close_browser_btn.setEnabled(is_visible)
            
            # Update teks tombol berdasarkan state
            if is_visible:
                self.close_browser_btn.setText("❌ Hide Browser")
            else:
                self.close_browser_btn.setText("❌ Close Browser")
        else:
            self.open_browser_btn.setEnabled(True)
            self.close_browser_btn.setEnabled(False)
            self.close_browser_btn.setText("❌ Hide Browser")

    def browser_back(self):
        """Browser back button"""
        if hasattr(self, 'browser') and self.browser:
            self.browser.back()

    def browser_forward(self):
        """Browser forward button"""
        if hasattr(self, 'browser') and self.browser:
            self.browser.forward()

    def browser_refresh(self):
        """Browser refresh button"""
        if hasattr(self, 'browser') and self.browser:
            self.browser.reload()

    def update_url_bar(self, url):
        """Update url bar when page changes"""
        if hasattr(self, 'url_bar') and self.url_bar:
            self.url_bar.setText(url.toString())

    def on_load_started(self):
        """Handle page load start"""
        if hasattr(self, 'url_bar') and self.url_bar:
            self.url_bar.setPlaceholderText("Loading...")

    def on_load_finished(self, ok):
        """Handle page load finish"""
        if hasattr(self, 'url_bar') and self.url_bar:
            if ok:
                self.url_bar.setPlaceholderText("Enter URL or search...")
            else:
                self.url_bar.setPlaceholderText("Failed to load page")

    # === PROXY METHODS ===
    def show_proxy_settings(self):
        """Show proxy settings dialog"""
        dialog = ProxySettingsDialog(self)
        dialog.exec()

    def set_proxy(self, proxy_config):
        """Set proxy configuration - untuk requests + browser (PyQt6 safe)"""
        try:
            self.current_proxy = proxy_config
            self.proxy_enabled = True
            self.apply_proxy_to_requests()

            # === Browser Proxy (QWebEngineView) ===
            from PyQt6.QtNetwork import QNetworkProxy

            proxy_type = proxy_config['type'].lower()
            server = proxy_config['server']
            port = proxy_config['port']

            if proxy_type.startswith("socks5"):
                qtype = QNetworkProxy.ProxyType.Socks5Proxy
            elif proxy_type.startswith("socks4"):
                qtype = QNetworkProxy.ProxyType.Socks4Proxy
            else:
                qtype = QNetworkProxy.ProxyType.HttpProxy

            qproxy = QNetworkProxy(qtype, server, port)
            QNetworkProxy.setApplicationProxy(qproxy)

            self.append_output("✓ Browser proxy applied via QNetworkProxy")

            # === Logging / konfirmasi ===
            proxy_info = f"{server}:{port}"
            if proxy_type != 'http':
                proxy_info += f" [{proxy_type.upper()}]"
            self.append_output(f"✓ Proxy configured: {proxy_info}")
            self.append_output(f"Note: Proxy applied to requests + browser")

            self.update_proxy_status()

        except Exception as e:
            self.append_output(f"✗ Proxy error: {e}")

    def enable_proxy(self):
        """Enable proxy - otomatis ganti IP Tor"""
        if not self.current_proxy:
            self.append_output("No proxy configured. Please set proxy first.")
            self.show_proxy_settings()
            return

        self.proxy_enabled = True
        self.apply_proxy_to_requests()
        self.append_output("✓ Proxy enabled for system/requests")
        self.append_output("ℹ Browser will use system proxy settings")

        # === Tambahan: jika proxy adalah Tor (127.0.0.1:9050), ganti IP otomatis ===
        try:
            if self.current_proxy['server'] == '127.0.0.1' and str(self.current_proxy['port']) == '9050':
                from stem import Signal
                from stem.control import Controller
                with Controller.from_port(port=9051) as c:
                    c.authenticate()
                    c.signal(Signal.NEWNYM)
                self.append_output("↻ Tor circuit renewed automatically (new IP)")
        except Exception as e:
            self.append_output(f"✗ Could not renew Tor IP automatically: {e}")

        self.update_proxy_status()

    def disable_proxy(self):
        """Disable proxy"""
        self.proxy_enabled = False
        self.apply_proxy_to_requests()
        self.append_output("Proxy disabled")
        self.update_proxy_status()

    def apply_proxy_to_requests(self):
        """Apply proxy settings to requests library"""
        if not self.current_proxy or not self.proxy_enabled:
            # Clear proxy dari environment
            for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']:
                if var in os.environ:
                    del os.environ[var]
            return

        try:
            proxy_type = self.current_proxy['type']
            server = self.current_proxy['server']
            port = self.current_proxy['port']

            # Build proxy URL
            proxy_url = f"{proxy_type}://{server}:{port}"

            # Set environment variables untuk requests
            os.environ['HTTP_PROXY'] = proxy_url
            os.environ['HTTPS_PROXY'] = proxy_url
            os.environ['http_proxy'] = proxy_url
            os.environ['https_proxy'] = proxy_url

            self.append_output(f"System proxy set: {proxy_url}")
            
        except Exception as e:
            self.append_output(f"System proxy error: {e}")

    def test_proxy_connection(self, proxy_config=None):
        """Test proxy connection"""
        config = proxy_config or self.current_proxy
        
        if not config:
            self.append_output("No proxy configured to test")
            return

        self.append_output(f"Testing proxy {config['server']}:{config['port']}...")

        import socket
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Auto-detect Tor Browser port
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect(("127.0.0.1", config["port"]))
        except Exception:
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect(("127.0.0.1", 9150))
                config["port"] = 9150
                self.append_output("Detected Tor Browser (using port 9150)")
            except Exception:
                pass
        finally:
            s.close()

        proxy_scheme = config["type"]
        if proxy_scheme.startswith("socks5"):
            proxy_scheme = "socks5h"

        proxies = {
            "http": f"{proxy_scheme}://{config['server']}:{config['port']}",
            "https": f"{proxy_scheme}://{config['server']}:{config['port']}"
        }

        test_url = "http://api.ipify.org?format=json"
        try:
            response = requests.get(test_url, proxies=proxies, timeout=30, verify=False)
            if response.status_code == 200:
                ip_info = response.json()
                self.append_output(f"✓ Proxy working! Your IP: {ip_info.get('ip', 'Unknown')}")
                return True
            else:
                self.append_output(f"✗ Proxy test failed (status {response.status_code})")
                return False

        except requests.exceptions.ConnectTimeout:
            self.append_output("✗ Proxy test failed: connection timed out (Tor may be slow)")
            return False
        except requests.exceptions.ProxyError as e:
            self.append_output(f"✗ Proxy error: {e}")
            return False
        except Exception as e:
            self.append_output(f"✗ Proxy test failed: {e}")
            return False

    # Proxy Auto
    def start_tor_auto_rotate(self):
        """Rotasi IP Tor otomatis setiap 5 menit"""
        from PyQt6.QtCore import QTimer

        self.tor_timer = QTimer(self)
        self.tor_timer.setInterval(300000)  # 5 menit = 300000 ms
        self.tor_timer.timeout.connect(self.rotate_tor_ip)
        self.tor_timer.start()
        self.append_output("Auto Tor IP rotation enabled (every 5 minutes)")

    def rotate_tor_ip(self):
        from stem import Signal
        from stem.control import Controller
        import requests
        
        # Ambil IP lama
        old_ip = self.get_current_ip()

        for port in [9051, 9151]:
            try:
                with Controller.from_port(port=port) as c:
                    c.authenticate()
                    c.signal(Signal.NEWNYM)

                    # Delay kecil agar circuit benar-benar berubah
                    QTimer.singleShot(2500, lambda p=port, old=old_ip: self.check_new_ip(p, old))
                    return
            except Exception:
                continue

        self.append_output("[red]✗ Tor ControlPort 9051/9151 not found[/]")

    def start_global_proxy_rotate(self):
        """Timer global: bisa rotate Tor atau File Proxy"""
        self.proxy_timer = QTimer()
        self.proxy_timer.timeout.connect(self.auto_rotate_proxy)
        self.proxy_timer.start(5 * 60 * 1000)   # 5 menit

    def detect_tor_socks(self):
        import socket

        for port in [9050, 9150]:
            s = socket.socket()
            try:
                s.settimeout(0.5)
                s.connect(("127.0.0.1", port))
                s.close()
                return port
            except:
                pass
        return None

    def get_current_ip(self):
        import requests

        socks_port = self.detect_tor_socks()
        if socks_port is None:
            return "Unknown"

        try:
            s = requests.get(
                "https://check.torproject.org/api/ip",
                proxies={
                    "http": f"socks5h://127.0.0.1:{socks_port}",
                    "https": f"socks5h://127.0.0.1:{socks_port}",
                },
                timeout=10
            ).json()

            return s.get("IP", "Unknown")

        except Exception:
            return "Unknown"

    def check_new_ip(self, port, old_ip):
        socks_port = self.detect_tor_socks()
        new_ip = self.get_current_ip()

        self.append_output(
            f"[cyan]SOCKS Port Used: {socks_port}[/]\n"
            f"[cyan]Old IP: {old_ip}[/]\n"
            f"[green]New IP: {new_ip}[/]\n"
            f"[green]✓ Tor IP rotated via port {port}[/]"
        )
        
    def update_proxy_status(self):
        """Update proxy status display"""
        self.update_session_info()
   
    def append_output(self, text):
        if not text:
            return

        # Deteksi ASCII table
        if any(ch in text for ch in ['─','│','┌','┐','└','┘','┬','┴','├','┤']):
            safe = (
                text.replace("<", "&lt;")
                    .replace(">", "&gt;")
            )

            # ====== COLOR BORDER (1 span UTUH — TIDAK MEMECAH KARAKTER) ======
            # border kiri/kanan tetap satu blok → garis tidak putus
            safe = f"<span style='color:#8be9fd;'>{safe}</span>"

            # ====== HEADER COLOR (baris 2) ======
            lines = safe.split("\n")
            if len(lines) >= 3:
                # Ambil hanya isi header tanpa memecah border
                lines[1] = re.sub(
                    r"(│)([^│]+)(│)",
                    lambda m: f"{m.group(1)}<span style='color:#ff79c6; font-weight:bold;'>{m.group(2)}</span>{m.group(3)}",
                    lines[1]
                )
            safe = "\n".join(lines)

            # ====== COLOR ISI TABEL (HIJAU, namun TIDAK menyentuh border │) ======
            safe = re.sub(
                r"(│)([^│]+)(│)",
                lambda m: f"{m.group(1)}<span style='color:#50fa7b;'>{m.group(2)}</span>{m.group(3)}",
                safe
            )

            # Tampilkan dalam <pre> monospace
            self.console_output.insertHtml(
                f"<pre style='font-family: monospace; white-space: pre;'>{safe}</pre>"
            )
            self.console_output.moveCursor(QTextCursor.MoveOperation.End)
            return

        # Output biasa
        html = self.rich_to_html(text)
        self.console_output.insertHtml(html + "<br>")
        self.console_output.moveCursor(QTextCursor.MoveOperation.End)

    def rich_to_html(self, text):
        import re

        color_map = {
            'black': '#000000', 'red': '#ff5555', 'green': '#50fa7b',
            'yellow': '#f1fa8c', 'blue': '#6272a4', 'magenta': '#ff79c6',
            'cyan': '#8be9fd', 'white': '#ffffff', 'orange': '#ffb86c',
            'bright_green': '#69ff94', 'bright_cyan': '#a5ffff',
        }

        # === MATCH multi-tag seperti [bold green] ===
        def repl(match):
            tags = match.group(1).split()  # pisah "bold green" → ["bold","green"]
            html_open = ""
            html_close = ""

            for tag in tags:
                tag = tag.lower()
                if tag == "bold":
                    html_open += "<b>"
                    html_close = "</b>" + html_close
                elif tag in color_map:
                    html_open += f"<span style='color:{color_map[tag]};'>"
                    html_close = "</span>" + html_close
            
            return html_open, html_close

        # Apply tags
        stack = []
        output = ""
        i = 0

        while i < len(text):
            if text[i] == "[":
                end = text.find("]", i)
                if end != -1:
                    tag_content = text[i+1:end]
                    if "/" == tag_content.strip():   # closing tag [/]
                        # Pop stack
                        if stack:
                            output += stack.pop()
                        i = end + 1
                        continue
                    else:
                        open_html, close_html = repl(re.match(r'(.*)', tag_content))
                        output += open_html
                        stack.append(close_html)
                        i = end + 1
                        continue
            
            output += text[i]
            i += 1

        # Close leftover tags
        while stack:
            output += stack.pop()

        return output

    def load_banner(self):
        self.append_output("[bold green]LazyFramework GUI v2.0[/]")
        self.append_output("[dim]Type 'help' or click modules to start[/]")

    def load_all_modules(self):
        """Load all modules into the list"""
        self.module_list.clear()
        modules = self.framework.metadata

        for module_path, meta in sorted(modules.items()):
            if not meta.get("options"):
                continue

            display_name = module_path.replace("modules/", "")
            item = QListWidgetItem(display_name)
            item.setData(Qt.ItemDataRole.UserRole, module_path)
            font = QFont("Hack", 10)
            item.setFont(font)
            # Color code by type
            if "/recon/" in module_path:
                item.setForeground(QColor("#ffffff"))  # Cyan
            elif "/strike/" in module_path:
                item.setForeground(QColor("#ffffff"))  # Red
            elif "/hold/" in module_path:
                item.setForeground(QColor("#ffffff"))  # Yellow
            elif "/ops/" in module_path:
                item.setForeground(QColor("#ffffff"))  # Green
            elif "/payload" in module_path:
                item.setForeground(QColor("#ffffff"))  # Pink

            self.module_list.addItem(item)

        self.update_session_info()

    def on_category_click(self):
        """Handle category button click"""
        button = self.sender()
        category = button.property('category')
        self.filter_modules_by_category(category)

    def filter_modules_by_category(self, category):
        """Filter modules by category"""
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            module_path = item.data(Qt.ItemDataRole.UserRole)

            if category == "all":
                item.setHidden(False)
            elif category == "payloads":
                item.setHidden("payload" not in module_path.lower())
            else:
                item.setHidden(f"/{category}/" not in module_path)

    def search_modules(self):
        """Search modules as user types"""
        search_text = self.search_input.text().lower()

        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            module_path = item.data(Qt.ItemDataRole.UserRole)
            meta = self.framework.metadata.get(module_path, {})
            description = meta.get("description", "").lower()

            matches = (search_text in module_path.lower() or
                       search_text in description)
            item.setHidden(not matches)

    def perform_search(self):
        """Perform search command"""
        search_text = self.search_input.text()
        if search_text:
            self.execute_command("search", [search_text])

    def load_selected_module(self, item):
        """Load selected module TANPA OUTPUT COMMAND KE CONSOLE"""
        module_path = item.data(Qt.ItemDataRole.UserRole)
        import shutil
        module_dir = os.path.dirname(module_path)
        pycache_dir = os.path.join(module_dir, "__pycache__")
        if os.path.exists(pycache_dir):
            try:
                shutil.rmtree(pycache_dir)
                self.append_output(f"[bold cyan][*] Cache dihapus: {pycache_dir}[/]")
            except Exception as e:
                self.append_output(f"[bold red][!] Gagal hapus cache: {e}[/]")
        try:
            # Pause global capture sementara
            self.capture.stop_capture()
            
            # Execute use command tanpa output ke console
            output_buffer = io.StringIO()
            with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
                self.framework.cmd_use([module_path])
            
            # Resume capture
            self.capture.start_capture()
            
            # Update UI state tanpa output ke console
            if self.framework.loaded_module:
                self.current_module = self.framework.loaded_module.name
                self.current_module_label.setText(f"Loaded: {self.current_module}")
                self.current_module_label.setStyleSheet("color: #50fa7b; font-weight: bold;")
                self.run_btn.setEnabled(True)
                self.back_btn.setEnabled(True)
                
                # Load module options
                self.load_module_options()
                
                # Show module info di tab Module Info (bukan console)
                self.show_module_info_in_tab()
                
        except Exception as e:
            self.append_output(f"Error loading module: {e}")

    def show_module_info_in_tab(self):
        """Show module info di tab Module Info saja"""
        try:
            # Pause global capture
            self.capture.stop_capture()
            
            # Capture info output
            output_buffer = io.StringIO()
            with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
                self.framework.cmd_info([])
            
            # Get the output
            info_output = output_buffer.getvalue()
            
            # Resume capture
            self.capture.start_capture()
            
            # Tampilkan di Module Info tab saja
            if info_output.strip():
                clean_info = re.sub(r'\x1b\[[0-9;]*[mG]', '', info_output)
                self.module_detail_info.setPlainText(clean_info)
                
            # Switch ke Module Info tab
            self.tabs.setCurrentIndex(2)
            
        except Exception as e:
            self.module_detail_info.setPlainText(f"Error loading module info: {e}")

    def execute_command(self, command=None, args=None):
        """Execute framework command"""
        if command is None:
            # Get command from input
            full_command = self.command_input.text().strip()
            if not full_command:
                return

            # Add to history
            self.command_history.append(full_command)
            self.history_index = len(self.command_history)

            # Parse command
            parts = full_command.split()
            command = parts[0]
            args = parts[1:] if len(parts) > 1 else []

            # Clear input
            self.command_input.clear()

        # Tampilkan command yang di-execute (kecuali untuk klik module)
        if command != "use" or not args or "modules/" not in args[0]:
            self.append_output(f"> {command} {' '.join(args)}")

        try:
            if hasattr(self.framework, f"cmd_{command}"):
                # Pause global capture selama command execution
                self.capture.stop_capture()

                # Redirect output sementara
                output_buffer = io.StringIO()
                with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
                    getattr(self.framework, f"cmd_{command}")(args)

                # Capture output dari command
                output = output_buffer.getvalue()
                if output.strip():
                    # Untuk command 'info', tampilkan di tab Module Info saja
                    if command == "info":
                        clean_info = re.sub(r'\x1b\[[0-9;]*[mG]', '', output)
                        self.module_detail_info.setPlainText(clean_info)
                        self.tabs.setCurrentIndex(2)  # Switch ke Module Info tab
                    else:
                        self.append_output(output)

                # Resume global capture
                self.capture.start_capture()

                # Update UI berdasarkan command
                if command == "use":
                    self.on_module_loaded()
                elif command == "back":
                    self.on_module_unloaded()

            else:
                self.append_output(f"Unknown command: {command}")

        except Exception as e:
            self.append_output(f"Error executing command: {e}")

        self.update_session_info()

    def on_module_loaded(self):
        """Handle when module is loaded"""
        if self.framework.loaded_module:
            self.current_module = self.framework.loaded_module.name
            self.current_module_label.setText(f"Loaded: {self.current_module}")
            self.current_module_label.setStyleSheet(
                "color: #50fa7b; font-weight: bold;")

            self.run_btn.setEnabled(True)
            self.back_btn.setEnabled(True)

            # Load module options
            self.load_module_options()

            # Show module info di tab Module Info
            self.show_module_info_in_tab()

    def on_module_unloaded(self):
        """Handle when module is unloaded"""
        self.current_module = None
        self.current_module_label.setText("No module loaded")
        self.current_module_label.setStyleSheet(
            "color: #ff5555; font-weight: bold;")

        self.run_btn.setEnabled(False)
        self.back_btn.setEnabled(False)

        # Clear options tab
        self.clear_options_tab()
        
        # Clear module info tab
        self.module_detail_info.clear()

    def load_module_options(self):
        """Load module options into options tab"""
        self.clear_options_tab()

        if not self.framework.loaded_module:
            return

        opts = self.framework.loaded_module.get_options()
        self.option_widgets = {}

        for name, info in opts.items():
            label = QLabel(name)
            value = str(info.get('value') or info.get('default') or "")
            required = info.get('required', False)
            description = info.get('description', 'No description available')

            if required:
                label.setStyleSheet("color: #ff5555; font-weight: bold;")
                label.setText(f"{name} *")
            else:
                label.setStyleSheet("color: #d4d4d4;")

            # Create input widget
            line_edit = QLineEdit(value)
            line_edit.setPlaceholderText(description)

            # Tooltip with full description
            line_edit.setToolTip(description)
            label.setToolTip(description)

            self.options_layout.addRow(label, line_edit)
            self.option_widgets[name] = line_edit

        # Switch to options tab
        self.tabs.setCurrentIndex(1)

    def clear_options_tab(self):
        """Clear options tab"""
        for i in reversed(range(self.options_layout.count())):
            item = self.options_layout.itemAt(i)
            if item.widget():
                item.widget().deleteLater()

    def run_module(self):
        """Run the current module dengan FIXED OUTPUT CAPTURE"""
        if not self.framework.loaded_module:
            self.append_output("No module loaded")
            return

        # Update options from GUI
        for name, widget in self.option_widgets.items():
            value = widget.text().strip()
            if value:
                try:
                    self.framework.loaded_module.set_option(name, value)
                    self.append_output(f"Set {name} => {value}")
                except Exception as e:
                    self.append_output(f"Error setting {name}: {e}")

        # Disable run button during execution
        self.run_btn.setEnabled(False)
        self.run_btn.setText("RUNNING...")

        # Gunakan ModuleRunner dengan subprocess patching
        self.module_runner = ModuleRunner(
            self.framework, self.framework.loaded_module)
        self.module_runner.output.connect(self.append_output)
        self.module_runner.finished.connect(self.on_module_finished)
        self.module_runner.start()

    def on_module_finished(self):
        """Handle module completion"""
        self.run_btn.setEnabled(True)
        self.run_btn.setText("START")
        self.append_output("[bold green][+] Module execution completed[/]")

    def unload_module(self):
        """Unload current module"""
        self.execute_command("back", [])

    def quick_command(self, command):
        """Execute quick command from buttons"""
        self.execute_command(command, [])

    def refresh_modules(self):
        """Refresh modules list"""
        self.framework.scan_modules()
        self.load_all_modules()
        self.append_output("Modules refreshed")

    def clear_console(self):
        """Clear console output"""
        self.console_output.clear()

    def change_font(self):
        """Open font selection dialog and apply to all text widgets"""
        font, ok = QFontDialog.getFont(self)
        if ok:
            # Terapkan font ke widget utama yang menampilkan teks
            self.console_output.setFont(font)
            self.module_detail_info.setFont(font)
            self.session_info.setFont(font)
            for i in range(self.module_list.count()):
                item = self.module_list.item(i)
                item.setFont(font)

            # Terapkan ke input field juga jika mau
            for widget in getattr(self, 'option_widgets', {}).values():
                widget.setFont(font)

            # Simpan ke framework session (opsional)
            self.framework.session['font'] = font.family()
            self.framework.session['font_size'] = font.pointSize()

            # Konfirmasi ke pengguna
            self.append_output(f"Font changed to {font.family()} ({font.pointSize()}pt)")

    def update_session_info(self):
        """Update session information dengan proxy status"""
        proxy_status = "Enabled" if self.proxy_enabled else "Disabled"
        proxy_details = ""
        
        if self.proxy_enabled and self.current_proxy:
            proxy_details = f"{self.current_proxy['server']}:{self.current_proxy['port']} ({self.current_proxy['type']})"

        info_text = f"""
User: {self.framework.session.get('user', 'unknown')}
Modules: {len(self.framework.modules)}
Loaded: {self.current_module or 'None'}
Framework: LazyFramework GUI
Proxy: {proxy_status}
{proxy_details}
        """.strip()

        self.session_info.setPlainText(info_text)

    def keyPressEvent(self, event):
        """Handle key press events"""
        if event.key() == Qt.Key.Key_Up:
            # Command history up
            if self.command_history and self.history_index > 0:
                self.history_index -= 1
                self.command_input.setText(
                    self.command_history[self.history_index])
        elif event.key() == Qt.Key.Key_Down:
            # Command history down
            if self.command_history and self.history_index < len(self.command_history) - 1:
                self.history_index += 1
                self.command_input.setText(
                    self.command_history[self.history_index])
            elif self.history_index == len(self.command_history) - 1:
                self.history_index = len(self.command_history)
                self.command_input.clear()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        """Cleanup saat aplikasi ditutup"""
        if hasattr(self, 'browser') and self.browser:
            self.browser.deleteLater()
        event.accept()

    def open_in_browser(self, url):
        """Open URL in browser panel"""
        # Pastikan browser panel terbuka
        if not self.browser or not self.browser.isVisible():
            self.open_browser_panel()
            # Tunggu sebentar untuk browser siap
            QTimer.singleShot(500, lambda: self._load_url(url))
        else:
            self._load_url(url)
            
    def _load_url(self, url):
        """Internal method to load URL in browser"""
        try:
            self.browser.setUrl(QUrl(url))
            self.append_output(f"[green]Opened in browser: {url}[/]")
        except Exception as e:
            self.append_output(f"[red]Failed to open URL: {e}[/]")

def run_gui():
    """Run the GUI application"""
    import platform
    
    # Fix environment variables for WebEngine
    os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--no-sandbox --disable-gpu-sandbox --disable-features=VizDisplayCompositor'
    os.environ['QT_QPA_PLATFORM'] = 'xcb'
    os.environ['QT_QUICK_BACKEND'] = 'software'
    os.environ["LIBGL_ALWAYS_SOFTWARE"] = "1"
    
    
    # Fix SSL certificates untuk Linux
    if platform.system() == "Linux":
        os.environ['QTWEBENGINE_DISABLE_SANDBOX'] = '1'
        # Coba berbagai path certificate yang umum
        cert_paths = [
            '/etc/ssl/certs/ca-certificates.crt',
            '/etc/ssl/certs/ca-bundle.crt',
            '/etc/pki/tls/certs/ca-bundle.crt'
        ]
        for cert_path in cert_paths:
            if os.path.exists(cert_path):
                os.environ['SSL_CERT_FILE'] = cert_path
                os.environ['REQUESTS_CA_BUNDLE'] = cert_path
                break
    
    app = QApplication(sys.argv)
    app.setApplicationName("LazyFramework GUI")
    app.setApplicationVersion("2.0")

    # Set dark palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(30, 30, 30))
    palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 45))
    palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(palette)

    win = LazyFrameworkGUI()
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
