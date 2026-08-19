"""
RANSOM SENSE — Desktop Real-Time Security Operations Center (SOC)
100% Native Desktop Python Application (Tkinter GUI - Zero Web Dependencies)

Features:
- Continuous Active File Scanning (scans all files in monitored folders continuously until stopped)
- Start / Stop / Resume Continuous Scanning Controls
- Live Threat Stream Table (Entropy, Threat Level, Risk Score, Quarantine Status)
- Heuristic Flags & Shannon Entropy Inspector
- Native Quarantine Vault Manager (View & Manage isolated threats)
- Interactive Threat Simulator
- Local File Scanner
- Live Backend Event Log Terminal
"""

import os
import sys
import json
import time
import threading
import urllib.request
import urllib.parse
import subprocess
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

BACKEND_URL = "http://127.0.0.1:8080"
BASE_DIR = Path(__file__).resolve().parent

# SOC Dark Theme Palette
BG_DARK = "#090d16"
BG_CARD = "#111827"
BG_CARD_ALT = "#1a2234"
BORDER_COLOR = "#24324d"
TEXT_PRIMARY = "#f1f5f9"
TEXT_MUTED = "#94a3b8"
ACCENT_CYAN = "#00f2fe"
ACCENT_PURPLE = "#7000ff"
ACCENT_GREEN = "#10b981"
ACCENT_AMBER = "#f59e0b"
ACCENT_RED = "#ef4444"
FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "Helvetica"
FONT_MONO = "Consolas" if sys.platform == "win32" else "Courier"

class RansomSenseFrontend(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RANSOM SENSE — Continuous File Threat & Ransomware Monitor")
        self.geometry("1200x840")
        self.minsize(980, 680)
        self.configure(bg=BG_DARK)

        # State
        self.is_connected = False
        self.is_scanning = True
        self.scan_history = []
        self.quarantine_items = []
        self.last_scanned_count = 0
        self.current_file_status = "Initializing..."

        # Build GUI
        self.setup_styles()
        self.create_header()
        self.create_scan_control_banner()
        self.create_hud_metrics()
        self.create_main_tabs()
        self.create_status_bar()

        # Background Sync Thread
        self.sync_active = True
        self.sync_thread = threading.Thread(target=self.background_sync_loop, daemon=True)
        self.sync_thread.start()

    def setup_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        
        self.style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        self.style.configure("TNotebook.Tab", 
                             background=BG_CARD, 
                             foreground=TEXT_MUTED, 
                             padding=[18, 8], 
                             font=(FONT_FAMILY, 10, "bold"),
                             borderwidth=0)
        self.style.map("TNotebook.Tab",
                       background=[("selected", BG_CARD_ALT)],
                       foreground=[("selected", ACCENT_CYAN)])

        self.style.configure("Treeview",
                             background=BG_CARD,
                             foreground=TEXT_PRIMARY,
                             fieldbackground=BG_CARD,
                             rowheight=30,
                             font=(FONT_FAMILY, 9),
                             borderwidth=0)
        self.style.configure("Treeview.Heading",
                             background=BG_CARD_ALT,
                             foreground=ACCENT_CYAN,
                             font=(FONT_FAMILY, 10, "bold"),
                             relief="flat",
                             padding=[6, 6])
        self.style.map("Treeview", background=[("selected", "#2d3748")])

    def create_header(self):
        header = tk.Frame(self, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR, height=72)
        header.pack(fill="x", padx=16, pady=(14, 6))

        # Brand Info
        brand = tk.Frame(header, bg=BG_CARD)
        brand.pack(side="left", padx=16, pady=10)

        icon_lbl = tk.Label(brand, text="🛡️", font=(FONT_FAMILY, 24), bg=BG_CARD, fg=ACCENT_CYAN)
        icon_lbl.pack(side="left", padx=(0, 12))

        title_sub = tk.Frame(brand, bg=BG_CARD)
        title_sub.pack(side="left")

        title_lbl = tk.Label(title_sub, text="RANSOM SENSE", font=(FONT_FAMILY, 15, "bold"), bg=BG_CARD, fg=TEXT_PRIMARY)
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(title_sub, text="Continuous Heuristic Malware & Shannon Entropy Scanner", font=(FONT_FAMILY, 9), bg=BG_CARD, fg=TEXT_MUTED)
        sub_lbl.pack(anchor="w")

        # Top Action Buttons
        btn_box = tk.Frame(header, bg=BG_CARD)
        btn_box.pack(side="right", padx=16, pady=10)

        self.btn_scan_file = tk.Button(btn_box, text="🔍 Scan Specific File", font=(FONT_FAMILY, 9, "bold"),
                                       bg="#2563eb", fg="white", activebackground="#3b82f6", activeforeground="white",
                                       relief="flat", padx=12, pady=6, cursor="hand2", command=self.pick_and_scan_file)
        self.btn_scan_file.pack(side="left", padx=5)

        self.btn_sim_threat = tk.Button(btn_box, text="⚡ Simulate Threat", font=(FONT_FAMILY, 9, "bold"),
                                        bg=ACCENT_RED, fg="white", activebackground="#dc2626", activeforeground="white",
                                        relief="flat", padx=12, pady=6, cursor="hand2", command=self.open_simulation_dialog)
        self.btn_sim_threat.pack(side="left", padx=5)

    def create_scan_control_banner(self):
        """Dedicated Continuous Scanning Control Banner"""
        banner = tk.Frame(self, bg=BG_CARD_ALT, highlightthickness=1, highlightbackground=BORDER_COLOR)
        banner.pack(fill="x", padx=16, pady=(0, 10))

        left_side = tk.Frame(banner, bg=BG_CARD_ALT)
        left_side.pack(side="left", padx=14, pady=8)

        self.lbl_scan_status_badge = tk.Label(
            left_side, text="🟢 CONTINUOUS SCANNING: ACTIVE",
            font=(FONT_FAMILY, 10, "bold"), bg="#064e3b", fg=ACCENT_GREEN,
            padx=10, pady=4, relief="flat"
        )
        self.lbl_scan_status_badge.pack(side="left", padx=(0, 12))

        self.lbl_scan_details = tk.Label(
            left_side, text="Scanning all files continuously until stopped...",
            font=(FONT_MONO, 9), bg=BG_CARD_ALT, fg=TEXT_PRIMARY
        )
        self.lbl_scan_details.pack(side="left")

        right_side = tk.Frame(banner, bg=BG_CARD_ALT)
        right_side.pack(side="right", padx=14, pady=8)

        # Toggle Button: Stop / Start Continuous Scanning
        self.btn_toggle_scan = tk.Button(
            right_side, text="⏹️ Stop Scanning", font=(FONT_FAMILY, 9, "bold"),
            bg="#dc2626", fg="white", activebackground="#b91c1c", activeforeground="white",
            relief="flat", padx=14, pady=4, cursor="hand2", command=self.toggle_continuous_scan
        )
        self.btn_toggle_scan.pack(side="left", padx=5)

        # Rescan All Button
        self.btn_rescan = tk.Button(
            right_side, text="↻ Rescan All Files", font=(FONT_FAMILY, 9, "bold"),
            bg="#374151", fg="white", activebackground="#4b5563", activeforeground="white",
            relief="flat", padx=12, pady=4, cursor="hand2", command=self.rescan_all_files
        )
        self.btn_rescan.pack(side="left", padx=5)

    def create_hud_metrics(self):
        hud = tk.Frame(self, bg=BG_DARK)
        hud.pack(fill="x", padx=16, pady=(0, 10))

        self.hud_cards = {}
        metrics = [
            ("scanned", "TOTAL FILES SCANNED", "0", ACCENT_CYAN, "📊"),
            ("clean", "CLEAN VERIFIED", "0", ACCENT_GREEN, "🟢"),
            ("suspicious", "SUSPICIOUS RISK", "0", ACCENT_AMBER, "🟡"),
            ("quarantined", "QUARANTINED THREATS", "0", ACCENT_RED, "🔒")
        ]

        for idx, (key, title, val, color, icon) in enumerate(metrics):
            card = tk.Frame(hud, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR)
            card.pack(side="left", fill="both", expand=True, padx=4 if idx > 0 else (0, 4))

            top = tk.Frame(card, bg=BG_CARD)
            top.pack(fill="x", padx=14, pady=(10, 2))

            tk.Label(top, text=icon, font=(FONT_FAMILY, 12), bg=BG_CARD, fg=color).pack(side="left")
            tk.Label(top, text=title, font=(FONT_FAMILY, 8, "bold"), bg=BG_CARD, fg=TEXT_MUTED).pack(side="left", padx=6)

            val_lbl = tk.Label(card, text=val, font=(FONT_FAMILY, 18, "bold"), bg=BG_CARD, fg=color)
            val_lbl.pack(anchor="w", padx=14, pady=(2, 10))

            self.hud_cards[key] = val_lbl

    def create_main_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 10))

        # Tab 1: Live Stream
        self.tab_stream = tk.Frame(self.notebook, bg=BG_DARK)
        self.notebook.add(self.tab_stream, text="  🛡️ Continuous Threat Stream  ")
        self.setup_stream_tab()

        # Tab 2: Quarantine Vault
        self.tab_quarantine = tk.Frame(self.notebook, bg=BG_DARK)
        self.notebook.add(self.tab_quarantine, text="  🔒 Quarantine Vault  ")
        self.setup_quarantine_tab()

        # Tab 3: Native Backend Event Logs
        self.tab_logs = tk.Frame(self.notebook, bg=BG_DARK)
        self.notebook.add(self.tab_logs, text="  📜 Backend Log Stream  ")
        self.setup_logs_tab()

        # Tab 4: System Monitor & Folders
        self.tab_system = tk.Frame(self.notebook, bg=BG_DARK)
        self.notebook.add(self.tab_system, text="  ⚙️ Engine Diagnostics & Folders  ")
        self.setup_system_tab()

    def setup_stream_tab(self):
        paned = tk.PanedWindow(self.tab_stream, orient="horizontal", bg=BG_DARK, bd=0, sashwidth=6)
        paned.pack(fill="both", expand=True, padx=4, pady=6)

        # Left: Live Stream Table
        left = tk.Frame(paned, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR)
        paned.add(left, minsize=560, stretch="always")

        top_bar = tk.Frame(left, bg=BG_CARD_ALT)
        top_bar.pack(fill="x", padx=10, pady=8)

        tk.Label(top_bar, text="CONTINUOUS FILE THREAT FEED (LIVE UPDATES)", font=(FONT_FAMILY, 9, "bold"), bg=BG_CARD_ALT, fg=ACCENT_CYAN).pack(side="left")

        columns = ("time", "filename", "entropy", "threat", "risk", "quarantine")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("time", text="Time")
        self.tree.heading("filename", text="File Name")
        self.tree.heading("entropy", text="Entropy")
        self.tree.heading("threat", text="Threat Rating")
        self.tree.heading("risk", text="Risk Score")
        self.tree.heading("quarantine", text="Quarantined")

        self.tree.column("time", width=80, anchor="center")
        self.tree.column("filename", width=220, anchor="w")
        self.tree.column("entropy", width=70, anchor="center")
        self.tree.column("threat", width=140, anchor="center")
        self.tree.column("risk", width=75, anchor="center")
        self.tree.column("quarantine", width=85, anchor="center")

        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        scroll.pack(side="right", fill="y", padx=(0, 10), pady=(0, 10))

        self.tree.bind("<<TreeviewSelect>>", self.on_item_selected)

        # Right: Heuristics & Entropy Inspector
        right = tk.Frame(paned, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR)
        paned.add(right, minsize=320, stretch="always")

        insp_top = tk.Frame(right, bg=BG_CARD_ALT)
        insp_top.pack(fill="x", padx=10, pady=8)

        tk.Label(insp_top, text="THREAT HEURISTICS & ENTROPY INSPECTOR", font=(FONT_FAMILY, 9, "bold"), bg=BG_CARD_ALT, fg=ACCENT_CYAN).pack(side="left")

        self.insp_text = tk.Text(right, bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_MONO, 9),
                                 wrap="word", relief="flat", padx=12, pady=10, highlightthickness=0)
        self.insp_text.pack(fill="both", expand=True)
        self.insp_text.insert("1.0", "Select any scanned file on the left to inspect its detailed Shannon entropy score, SHA-256 hash, and heuristic rule flags.")
        self.insp_text.config(state="disabled")

    def setup_quarantine_tab(self):
        q_frame = tk.Frame(self.tab_quarantine, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR)
        q_frame.pack(fill="both", expand=True, padx=4, pady=6)

        toolbar = tk.Frame(q_frame, bg=BG_CARD_ALT)
        toolbar.pack(fill="x", padx=10, pady=8)

        tk.Label(toolbar, text="ISOLATED THREAT VAULT (./quarantine/)", font=(FONT_FAMILY, 9, "bold"), bg=BG_CARD_ALT, fg=ACCENT_RED).pack(side="left")

        tk.Button(toolbar, text="📂 Open Folder", font=(FONT_FAMILY, 8), bg="#374151", fg="white",
                  relief="flat", padx=8, pady=2, command=self.open_quarantine_folder).pack(side="right", padx=6)

        tk.Button(toolbar, text="↻ Refresh", font=(FONT_FAMILY, 8), bg="#374151", fg="white",
                  relief="flat", padx=8, pady=2, command=self.fetch_quarantine_items).pack(side="right")

        q_cols = ("filename", "size", "date")
        self.q_tree = ttk.Treeview(q_frame, columns=q_cols, show="headings", selectmode="browse")
        self.q_tree.heading("filename", text="Quarantined File Name")
        self.q_tree.heading("size", text="Size")
        self.q_tree.heading("date", text="Date Isolated")

        self.q_tree.column("filename", width=420, anchor="w")
        self.q_tree.column("size", width=100, anchor="center")
        self.q_tree.column("date", width=180, anchor="center")

        q_scroll = ttk.Scrollbar(q_frame, orient="vertical", command=self.q_tree.yview)
        self.q_tree.configure(yscrollcommand=q_scroll.set)

        self.q_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        q_scroll.pack(side="right", fill="y", padx=(0, 10), pady=(0, 10))

    def setup_logs_tab(self):
        logs_frame = tk.Frame(self.tab_logs, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR)
        logs_frame.pack(fill="both", expand=True, padx=4, pady=6)

        toolbar = tk.Frame(logs_frame, bg=BG_CARD_ALT)
        toolbar.pack(fill="x", padx=10, pady=8)

        tk.Label(toolbar, text="NATIVE BACKEND SERVER LOG STREAM (logs/server.log)", font=(FONT_FAMILY, 9, "bold"), bg=BG_CARD_ALT, fg=ACCENT_CYAN).pack(side="left")

        tk.Button(toolbar, text="🗑️ Clear Logs", font=(FONT_FAMILY, 8), bg="#dc2626", fg="white",
                  relief="flat", padx=8, pady=2, command=self.clear_backend_logs).pack(side="right", padx=6)

        tk.Button(toolbar, text="↻ Refresh Logs", font=(FONT_FAMILY, 8), bg="#374151", fg="white",
                  relief="flat", padx=8, pady=2, command=self.fetch_server_logs).pack(side="right")

        self.log_text = tk.Text(logs_frame, bg="#070a10", fg="#38bdf8", font=(FONT_MONO, 9),
                                wrap="none", relief="flat", padx=12, pady=10)
        log_scroll_y = ttk.Scrollbar(logs_frame, orient="vertical", command=self.log_text.yview)
        log_scroll_x = ttk.Scrollbar(logs_frame, orient="horizontal", command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=log_scroll_y.set, xscrollcommand=log_scroll_x.set)

        log_scroll_x.pack(side="bottom", fill="x")
        self.log_text.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        log_scroll_y.pack(side="right", fill="y", padx=(0, 10), pady=(0, 10))

    def setup_system_tab(self):
        container = tk.Frame(self.tab_system, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=8, pady=8)

        # Card 1: Simulation Triggers
        sim_card = tk.Frame(container, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR)
        sim_card.pack(fill="x", pady=6)

        tk.Label(sim_card, text="🎯 THREAT SIMULATION TRIGGER SUITE", font=(FONT_FAMILY, 10, "bold"), bg=BG_CARD, fg=ACCENT_CYAN).pack(anchor="w", padx=14, pady=(12, 6))

        tk.Label(sim_card, text="Generate simulated threat payloads directly into ./monitored_downloads to test live heuristic defense:",
                 font=(FONT_FAMILY, 9), bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w", padx=14, pady=(0, 10))

        btn_row1 = tk.Frame(sim_card, bg=BG_CARD)
        btn_row1.pack(fill="x", padx=14, pady=(0, 14))

        tk.Button(btn_row1, text="📄 Clean PDF (Low Entropy)", font=(FONT_FAMILY, 9), bg=ACCENT_GREEN, fg="white",
                  relief="flat", padx=12, pady=6, command=lambda: self.trigger_simulation("clean")).pack(side="left", padx=(0, 10))

        tk.Button(btn_row1, text="⚠️ Macro DOCX (PowerShell/VBA)", font=(FONT_FAMILY, 9), bg=ACCENT_AMBER, fg="white",
                  relief="flat", padx=12, pady=6, command=lambda: self.trigger_simulation("suspicious")).pack(side="left", padx=(0, 10))

        tk.Button(btn_row1, text="💀 Malicious Ransomware (.pdf.exe)", font=(FONT_FAMILY, 9), bg=ACCENT_RED, fg="white",
                  relief="flat", padx=12, pady=6, command=lambda: self.trigger_simulation("ransomware")).pack(side="left")

        # Card 2: Monitored Folders
        dir_card = tk.Frame(container, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR)
        dir_card.pack(fill="x", pady=6)

        tk.Label(dir_card, text="📁 MONITORED FILE SYSTEM LOCATIONS", font=(FONT_FAMILY, 10, "bold"), bg=BG_CARD, fg=ACCENT_CYAN).pack(anchor="w", padx=14, pady=(12, 6))

        btn_row2 = tk.Frame(dir_card, bg=BG_CARD)
        btn_row2.pack(fill="x", padx=14, pady=(0, 14))

        tk.Button(btn_row2, text="📂 Monitored Downloads Folder", font=(FONT_FAMILY, 9), bg="#374151", fg="white",
                  relief="flat", padx=12, pady=6, command=self.open_monitored_folder).pack(side="left", padx=(0, 10))

        tk.Button(btn_row2, text="📂 User PC Downloads Folder", font=(FONT_FAMILY, 9), bg="#374151", fg="white",
                  relief="flat", padx=12, pady=6, command=self.open_user_downloads).pack(side="left", padx=(0, 10))

        tk.Button(btn_row2, text="📂 Quarantine Storage", font=(FONT_FAMILY, 9), bg="#374151", fg="white",
                  relief="flat", padx=12, pady=6, command=self.open_quarantine_folder).pack(side="left")

    def create_status_bar(self):
        status = tk.Frame(self, bg=BG_CARD, highlightthickness=1, highlightbackground=BORDER_COLOR, height=32)
        status.pack(fill="x", side="bottom")

        self.status_dot = tk.Label(status, text="●", font=(FONT_FAMILY, 10), bg=BG_CARD, fg=ACCENT_AMBER)
        self.status_dot.pack(side="left", padx=(12, 4), pady=4)

        self.status_label = tk.Label(status, text="Connecting to Ransom Sense Daemon...",
                                     font=(FONT_FAMILY, 9), bg=BG_CARD, fg=TEXT_MUTED)
        self.status_label.pack(side="left", pady=4)

        self.clock_label = tk.Label(status, text="", font=(FONT_FAMILY, 9), bg=BG_CARD, fg=TEXT_MUTED)
        self.clock_label.pack(side="right", padx=12, pady=4)
        self.update_clock()

    def update_clock(self):
        self.clock_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.after(1000, self.update_clock)

    # =========================================================================
    # CONTINUOUS SCANNING CONTROL ACTIONS
    # =========================================================================
    def toggle_continuous_scan(self):
        threading.Thread(target=self._toggle_scan_thread, daemon=True).start()

    def _toggle_scan_thread(self):
        try:
            req = urllib.request.Request(f"{BACKEND_URL}/api/scanner/toggle", data=b"{}", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as res:
                data = json.loads(res.read().decode())
                is_active = data.get("isWatching", True)
                self.after(0, lambda: self.update_scan_state(is_active))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Control Error", f"Could not toggle scanner:\n{e}"))

    def rescan_all_files(self):
        threading.Thread(target=self._rescan_thread, daemon=True).start()

    def _rescan_thread(self):
        try:
            req = urllib.request.Request(f"{BACKEND_URL}/api/scanner/rescan-all", data=b"{}", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as res:
                self.after(0, lambda: self.lbl_scan_details.config(text="Resetting cache and rescanning all monitored files..."))
        except Exception:
            pass

    def update_scan_state(self, is_active: bool):
        self.is_scanning = is_active
        if is_active:
            self.lbl_scan_status_badge.config(
                text="🟢 CONTINUOUS SCANNING: ACTIVE",
                bg="#064e3b", fg=ACCENT_GREEN
            )
            self.btn_toggle_scan.config(
                text="⏹️ Stop Scanning",
                bg="#dc2626", activebackground="#b91c1c"
            )
            self.lbl_scan_details.config(text="Actively scanning all files continuously until stopped...")
        else:
            self.lbl_scan_status_badge.config(
                text="🔴 SCANNING: STOPPED MANUALLY",
                bg="#7f1d1d", fg=ACCENT_RED
            )
            self.btn_toggle_scan.config(
                text="▶️ Start Continuous Scan",
                bg="#16a34a", activebackground="#15803d"
            )
            self.lbl_scan_details.config(text="Scanning is currently paused. Click 'Start Continuous Scan' to resume.")

    # =========================================================================
    # BACKEND DATA SYNCHRONIZATION
    # =========================================================================
    def background_sync_loop(self):
        while self.sync_active:
            try:
                # 1. Fetch Scanner Status
                req = urllib.request.Request(f"{BACKEND_URL}/api/scanner/status")
                with urllib.request.urlopen(req, timeout=2) as res:
                    data = json.loads(res.read().decode())
                    if data.get("success"):
                        self.is_connected = True
                        dirs_cnt = len(data.get("monitoredDirectories", []))
                        is_active = data.get("isWatching", True)
                        current_file = data.get("currentFile", "")
                        cycle = data.get("cycleCount", 1)

                        self.after(0, lambda: self.update_connection_status(True, f"Ransom Sense Engine Active • Cycle #{cycle} • Monitoring {dirs_cnt} Folders"))
                        
                        if is_active != self.is_scanning:
                            self.after(0, lambda: self.update_scan_state(is_active))
                        
                        if is_active and current_file:
                            self.after(0, lambda: self.lbl_scan_details.config(text=f"Current activity: {current_file}"))

                # 2. Fetch Latest Scan History
                req_h = urllib.request.Request(f"{BACKEND_URL}/api/scanner/history")
                with urllib.request.urlopen(req_h, timeout=2) as res_h:
                    hist_data = json.loads(res_h.read().decode())
                    if hist_data.get("success"):
                        new_history = hist_data.get("history", [])
                        if len(new_history) != self.last_scanned_count:
                            self.scan_history = new_history
                            self.last_scanned_count = len(new_history)
                            self.after(0, self.render_history_table)

                # 3. Fetch Server Logs
                req_l = urllib.request.Request(f"{BACKEND_URL}/api/logs")
                with urllib.request.urlopen(req_l, timeout=2) as res_l:
                    logs_txt = res_l.read().decode()
                    self.after(0, lambda: self.render_server_logs(logs_txt))

                # 4. Fetch Quarantine List
                req_q = urllib.request.Request(f"{BACKEND_URL}/api/quarantine/list")
                with urllib.request.urlopen(req_q, timeout=2) as res_q:
                    q_data = json.loads(res_q.read().decode())
                    if q_data.get("success"):
                        self.quarantine_items = q_data.get("items", [])
                        self.after(0, self.render_quarantine_table)

            except Exception:
                self.is_connected = False
                self.after(0, lambda: self.update_connection_status(False, "Ransom Sense Backend Engine Offline (Run backend_server.py)"))

            time.sleep(1.2)

    def update_connection_status(self, connected: bool, message: str):
        if connected:
            self.status_dot.config(fg=ACCENT_GREEN)
            self.status_label.config(text=f"● {message}", fg=TEXT_PRIMARY)
        else:
            self.status_dot.config(fg=ACCENT_RED)
            self.status_label.config(text=f"● {message}", fg=ACCENT_RED)

    def render_history_table(self):
        clean_cnt = sum(1 for x in self.scan_history if x.get("threatLevel") == "CLEAN")
        susp_cnt = sum(1 for x in self.scan_history if x.get("threatLevel") == "SUSPICIOUS")
        quar_cnt = sum(1 for x in self.scan_history if x.get("quarantined") or x.get("threatLevel") == "MALICIOUS_RANSOMWARE_RISK")

        self.hud_cards["scanned"].config(text=str(len(self.scan_history)))
        self.hud_cards["clean"].config(text=str(clean_cnt))
        self.hud_cards["suspicious"].config(text=str(susp_cnt))
        self.hud_cards["quarantined"].config(text=str(quar_cnt))

        # Save selected item
        selected_id = self.tree.selection()
        selected_file = None
        if selected_id:
            val = self.tree.item(selected_id[0], "values")
            if val and len(val) > 1:
                selected_file = val[1]

        for item in self.tree.get_children():
            self.tree.delete(item)

        for scan in self.scan_history:
            ts = scan.get("timestamp", "")
            time_disp = ts[11:19] if len(ts) >= 19 else ts
            fn = scan.get("filename", "")
            ent = f"{scan.get('entropy', 0.0):.2f}"
            thr = scan.get("threatLevel", "CLEAN")
            rsk = f"{scan.get('riskScore', 0)}/100"
            quar = "🔒 YES" if scan.get("quarantined") else "NO"

            node = self.tree.insert("", "end", values=(time_disp, fn, ent, thr, rsk, quar))
            if selected_file and fn == selected_file:
                self.tree.selection_set(node)

    def render_quarantine_table(self):
        for item in self.q_tree.get_children():
            self.q_tree.delete(item)

        for item in self.quarantine_items:
            fn = item.get("name", "")
            sz = item.get("size", "")
            dt = item.get("modified", "")
            dt_disp = dt.replace("T", " ")[:19]
            self.q_tree.insert("", "end", values=(fn, sz, dt_disp))

    def on_item_selected(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        values = item.get("values", [])
        if not values:
            return

        filename = values[1]
        matching = next((x for x in self.scan_history if x.get("filename") == filename), None)
        if not matching:
            return

        heuristics = matching.get("heuristics", {})
        flags = heuristics.get("flags", [])
        flags_str = "\n".join([f"  • {f}" for f in flags]) if flags else "  (None - standard benign profile)"

        report = f"""======================================================
THREAT ANALYSIS REPORT: {matching.get('filename')}
======================================================
File Path:     {matching.get('filePath')}
File Size:     {matching.get('fileSizeFormatted')} ({matching.get('fileSize')} bytes)
Timestamp:     {matching.get('timestamp')}
SHA-256 Hash:  {matching.get('sha256')}

SHANNON ENTROPY SCORE:
  Entropy Value: {matching.get('entropy')} / 8.0
  Analysis:      {'HIGH ENTROPY (Encrypted payload / Ransomware indicator)' if matching.get('entropy',0) > 7.5 else 'Normal / Low Entropy'}

HEURISTIC CLASSIFICATION:
  Threat Level:  {matching.get('threatLevel')}
  Risk Score:    {matching.get('riskScore')} / 100
  PE Binary:     {'Yes (MZ Header detected)' if heuristics.get('isPEExecutable') else 'No'}
  Quarantined:   {'YES (Moved to ./quarantine/)' if matching.get('quarantined') else 'NO'}

SECURITY FLAGS DETECTED:
{flags_str}
"""
        self.insp_text.config(state="normal")
        self.insp_text.delete("1.0", "end")
        self.insp_text.insert("1.0", report)
        self.insp_text.config(state="disabled")

    def render_server_logs(self, text: str):
        self.log_text.delete("1.0", "end")
        self.log_text.insert("end", text)
        self.log_text.see("end")

    # =========================================================================
    # USER ACTIONS
    # =========================================================================
    def pick_and_scan_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Scan with Ransom Sense")
        if not file_path:
            return
        threading.Thread(target=self._scan_file_request, args=(file_path,), daemon=True).start()

    def _scan_file_request(self, file_path: str):
        try:
            req_data = json.dumps({"filePath": file_path}).encode("utf-8")
            req = urllib.request.Request(f"{BACKEND_URL}/api/scanner/scan-now", data=req_data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode())
                if data.get("success"):
                    self.after(0, lambda: messagebox.showinfo("Scan Completed", f"Successfully scanned file:\n{Path(file_path).name}\n\nThreat Rating: {data['scanResult']['threatLevel']} (Risk: {data['scanResult']['riskScore']}/100)"))
                    self.fetch_latest_history()
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Scan Error", f"Could not scan file:\n{e}"))

    def trigger_simulation(self, sim_type: str):
        threading.Thread(target=self._simulate_request, args=(sim_type,), daemon=True).start()

    def _simulate_request(self, sim_type: str):
        try:
            req_data = json.dumps({"type": sim_type}).encode("utf-8")
            req = urllib.request.Request(f"{BACKEND_URL}/api/scanner/simulate", data=req_data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode())
                if data.get("success"):
                    self.after(0, lambda: self.status_label.config(text=f"● Simulated {sim_type.upper()} payload created: {data.get('filename')}", fg=ACCENT_CYAN))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Simulation Error", f"Failed to simulate threat:\n{e}"))

    def open_simulation_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Trigger Threat Simulation")
        dialog.geometry("420x280")
        dialog.configure(bg=BG_CARD)
        dialog.transient(self)
        dialog.grab_set()

        lbl = tk.Label(dialog, text="Select Simulation Threat Profile", font=(FONT_FAMILY, 11, "bold"), bg=BG_CARD, fg=TEXT_PRIMARY)
        lbl.pack(pady=(16, 12))

        tk.Button(dialog, text="📄 Clean PDF Document", font=(FONT_FAMILY, 10), bg=ACCENT_GREEN, fg="white",
                  relief="flat", padx=12, pady=6, command=lambda: [self.trigger_simulation("clean"), dialog.destroy()]).pack(fill="x", padx=24, pady=4)

        tk.Button(dialog, text="⚠️ Suspicious Macro DOCX", font=(FONT_FAMILY, 10), bg=ACCENT_AMBER, fg="white",
                  relief="flat", padx=12, pady=6, command=lambda: [self.trigger_simulation("suspicious"), dialog.destroy()]).pack(fill="x", padx=24, pady=4)

        tk.Button(dialog, text="💀 Malicious Ransomware (.pdf.exe)", font=(FONT_FAMILY, 10), bg=ACCENT_RED, fg="white",
                  relief="flat", padx=12, pady=6, command=lambda: [self.trigger_simulation("ransomware"), dialog.destroy()]).pack(fill="x", padx=24, pady=4)

    def fetch_latest_history(self):
        threading.Thread(target=self._fetch_history_thread, daemon=True).start()

    def _fetch_history_thread(self):
        try:
            req = urllib.request.Request(f"{BACKEND_URL}/api/scanner/history")
            with urllib.request.urlopen(req, timeout=3) as res:
                data = json.loads(res.read().decode())
                if data.get("success"):
                    self.scan_history = data.get("history", [])
                    self.after(0, self.render_history_table)
        except Exception:
            pass

    def fetch_quarantine_items(self):
        threading.Thread(target=self._fetch_quarantine_thread, daemon=True).start()

    def _fetch_quarantine_thread(self):
        try:
            req = urllib.request.Request(f"{BACKEND_URL}/api/quarantine/list")
            with urllib.request.urlopen(req, timeout=3) as res:
                data = json.loads(res.read().decode())
                if data.get("success"):
                    self.quarantine_items = data.get("items", [])
                    self.after(0, self.render_quarantine_table)
        except Exception:
            pass

    def fetch_server_logs(self):
        try:
            req = urllib.request.Request(f"{BACKEND_URL}/api/logs")
            with urllib.request.urlopen(req, timeout=3) as res:
                logs_txt = res.read().decode()
                self.render_server_logs(logs_txt)
        except Exception:
            pass

    def clear_backend_logs(self):
        if not messagebox.askyesno("Clear Logs", "Are you sure you want to clear backend server log files?"):
            return
        try:
            req = urllib.request.Request(f"{BACKEND_URL}/api/logs", method="DELETE")
            with urllib.request.urlopen(req, timeout=3) as res:
                self.fetch_server_logs()
        except Exception as e:
            messagebox.showerror("Error", f"Could not clear logs: {e}")

    def open_quarantine_folder(self):
        q_dir = BASE_DIR / "quarantine"
        q_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            os.startfile(q_dir)
        elif sys.platform == "darwin":
            subprocess.run(["open", str(q_dir)])
        else:
            subprocess.run(["xdg-open", str(q_dir)])

    def open_monitored_folder(self):
        m_dir = BASE_DIR / "monitored_downloads"
        m_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            os.startfile(m_dir)
        elif sys.platform == "darwin":
            subprocess.run(["open", str(m_dir)])
        else:
            subprocess.run(["xdg-open", str(m_dir)])

    def open_user_downloads(self):
        user_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or str(Path.home())
        d_dir = Path(user_home) / "Downloads"
        if d_dir.exists():
            if sys.platform == "win32":
                os.startfile(d_dir)
            elif sys.platform == "darwin":
                subprocess.run(["open", str(d_dir)])
            else:
                subprocess.run(["xdg-open", str(d_dir)])

if __name__ == "__main__":
    app = RansomSenseFrontend()
    app.mainloop()
