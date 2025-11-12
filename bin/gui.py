# gui.py
import sys
import threading
import shlex
import time
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont
from rich.console import Console as RichConsole

from lazyframework import LazyFramework

class RichCapture(QObject):
    output_signal = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.console = RichConsole(force_terminal=True, width=120)
    def print(self, *args, **kwargs):
        with self.console.capture() as cap:
            self.console.print(*args, **kwargs)
        self.output_signal.emit(cap.get())

class GUIFramework(QMainWindow):
    def __init__(self):
        super().__init__()
        self.framework = LazyFramework()
        self.capture = RichCapture()
        self.capture.output_signal.connect(self.append_output)
        self.framework.console = self.capture

        self.input_queue = threading.Queue()
        self.thread = threading.Thread(target=self.repl_loop, daemon=True)
        self.thread.start()

        self.init_ui()
        self.append_output(self.framework.get_random_banner())

    def init_ui(self):
        self.setWindowTitle("LazyFramework GUI")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet("background: #1e1e1e; color: #d4d4d4;")

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        header = QLabel("LAZY FRAMEWORK")
        header.setStyleSheet("font-size: 24px; color: #00ff00; font-weight: bold;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Console Tab
        console_tab = QWidget()
        cl = QVBoxLayout(console_tab)
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        self.output.setStyleSheet("background: #0d0d0d; color: #d4d4d4;")
        cl.addWidget(self.output)

        input_layout = QHBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.returnPressed.connect(self.send_command)
        btn = QPushButton("Run")
        btn.clicked.connect(self.send_command)
        btn.setStyleSheet("background: #00ff00; color: black;")
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(btn)
        cl.addLayout(input_layout)
        tabs.addTab(console_tab, "Console")

        # Modules Tab
        mod_tab = QWidget()
        ml = QVBoxLayout(mod_tab)
        btns = QHBoxLayout()
        for t in ["All", "Recon", "Strike", "Hold", "Ops", "Payloads"]:
            b = QPushButton(t)
            b.clicked.connect(lambda _, x=t.lower(): self.load_modules(x))
            b.setStyleSheet("background: #333; color: white;")
            btns.addWidget(b)
        ml.addLayout(btns)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Module", "Rank", "Type", "Desc"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(self.use_from_table)
        ml.addWidget(self.table)
        tabs.addTab(mod_tab, "Modules")

    def repl_loop(self):
        while True:
            try:
                cmd = self.input_queue.get(timeout=0.1)
                if cmd is None: continue
                parts = shlex.split(cmd)
                if not parts: continue
                c, a = parts[0], parts[1:]
                if c in ("exit", "quit"): break
                getattr(self.framework, f"cmd_{c}", lambda x: self.append_output("Unknown cmd"))(a)
            except:
                time.sleep(0.1)

    def send_command(self):
        cmd = self.input_field.text().strip()
        if cmd:
            self.append_output(f"[bold cyan]lzf >[/bold cyan] {cmd}")
            self.input_field.clear()
            self.input_queue.put(cmd)

    def append_output(self, text):
        text = text.replace("[bold]", "<b>").replace("[/bold]", "</b>")
        text = text.replace("[red]", "<span style='color:#ff5555'>").replace("[/red]", "</span>")
        text = text.replace("[green]", "<span style='color:#50fa7b'>").replace("[/green]", "</span>")
        text = text.replace("[yellow]", "<span style='color:#f1fa8c'>").replace("[/yellow]", "</span>")
        text = text.replace("[cyan]", "<span style='color:#8be9fd'>").replace("[/cyan]", "</span>")
        self.output.append(text)

    def load_modules(self, typ):
        self.table.setRowCount(0)
        modules = self.framework.metadata
        if typ != "all":
            modules = {k: v for k, v in modules.items() if f"/{typ}/" in k.lower() or (typ == "payloads" and "payload" in k.lower())}
        self.table.setRowCount(len(modules))
        for i, (k, m) in enumerate(sorted(modules.items())):
            if not m.get("options"): continue
            name = k.replace("modules/", "")
            rank = m.get("rank", "Normal")
            typ = k.split("/")[1] if len(k.split("/")) > 1 else "?"
            desc = m.get("description", "N/A")
            self.table.setItem(i, 0, QTableWidgetItem(name))
            self.table.setItem(i, 1, QTableWidgetItem(rank))
            self.table.setItem(i, 2, QTableWidgetItem(typ))
            self.table.setItem(i, 3, QTableWidgetItem(desc))

    def use_from_table(self):
        row = self.table.currentRow()
        if row >= 0:
            mod = self.table.item(row, 0).text()
            self.input_queue.put(f"use modules/{mod}")

def run_gui():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = GUIFramework()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    run_gui()
