"""
RANSOM SENSE — Backend Security Engine & Continuous Heuristic Scanner Daemon
100% Native Python Service running locally on your PC (Zero Web Dependencies)

Features:
- Continuous Active File Scanning (scans all files in monitored folders continuously until manually stopped)
- Start / Stop / Resume Scanning controls via IPC / REST API
- Shannon Entropy Calculation Engine (math.log2) for instant AES ransomware detection
- Static Heuristic Security Scanner (PE/MZ headers, double extensions, suspicious script patterns)
- Automated Threat Isolation & Quarantine to ./quarantine/
- Colorized Terminal Console showing all live backend processes and security events
"""

import os
import sys
import time
import json
import math
import hashlib
import threading
import queue
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime
from pathlib import Path

# Configure UTF-8 for Windows Console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ============================================================================
# CONFIGURATION & DIRECTORIES
# ============================================================================
PORT = 8080
BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
QUARANTINE_DIR = BASE_DIR / "quarantine"
LOCAL_MONITORED_DIR = BASE_DIR / "monitored_downloads"

user_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or str(Path.home())
USER_DOWNLOADS_DIR = Path(user_home) / "Downloads"

SERVER_LOG_FILE = LOGS_DIR / "server.log"
SERVER_JSONL_FILE = LOGS_DIR / "server_logs.jsonl"

for d in [LOGS_DIR, QUARANTINE_DIR, LOCAL_MONITORED_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ANSI Terminal Colors
COLOR_CYAN = "\033[96m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_PURPLE = "\033[95m"
COLOR_BLUE = "\033[94m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

def print_banner():
    banner = f"""
{COLOR_CYAN}{COLOR_BOLD}================================================================================
             RANSOM SENSE -- NATIVE PC THREAT & RANSOMWARE ENGINE              
      Continuous File Scanner * Shannon Entropy Analysis * Threat Quarantine   
================================================================================{COLOR_RESET}
  {COLOR_GREEN}* MODE:{COLOR_RESET}    CONTINUOUS ACTIVE SCANNING (Runs until manually stopped)
  {COLOR_GREEN}* PORT:{COLOR_RESET}    {PORT} (Local IPC Endpoint)
  {COLOR_GREEN}* LOGS:{COLOR_RESET}    {SERVER_LOG_FILE}
  {COLOR_GREEN}* WATCHING DIRECTORIES:{COLOR_RESET}
      [1] {LOCAL_MONITORED_DIR}
      [2] {USER_DOWNLOADS_DIR}
{COLOR_CYAN}--------------------------------------------------------------------------------{COLOR_RESET}
"""
    try:
        print(banner)
    except Exception:
        print("RANSOM SENSE -- BACKEND ENGINE RUNNING on port " + str(PORT))

# ============================================================================
# AUDIT LOGGING SYSTEM
# ============================================================================
log_lock = threading.Lock()

def log_backend_message(source: str, msg: str, log_type: str = "INFO", component: str = "Security Engine"):
    timestamp = datetime.now().isoformat()
    type_str = log_type.upper()
    formatted_line = f"[{timestamp}] [{type_str}] [{source}] [{component}] {msg}\n"
    json_record = json.dumps({
        "timestamp": timestamp,
        "source": source,
        "type": type_str,
        "component": component,
        "msg": msg
    }) + "\n"

    with log_lock:
        try:
            with open(SERVER_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(formatted_line)
            with open(SERVER_JSONL_FILE, "a", encoding="utf-8") as f:
                f.write(json_record)
        except Exception as e:
            pass

    color = COLOR_GREEN if type_str == "INFO" else (COLOR_YELLOW if type_str in ["WARN", "WARNING"] else (COLOR_RED if type_str == "ERROR" else COLOR_CYAN))
    time_short = datetime.now().strftime("%H:%M:%S")
    try:
        print(f"{COLOR_BLUE}[{time_short}]{COLOR_RESET} {color}[{type_str:7s}]{COLOR_RESET} {COLOR_PURPLE}[{source}]{COLOR_RESET} {msg}")
    except Exception:
        pass

# ============================================================================
# CONTINUOUS REAL-TIME FILE SECURITY SCANNER DAEMON
# ============================================================================
class FileSecurityWatcher:
    def __init__(self):
        self.watch_dirs = [LOCAL_MONITORED_DIR]
        if USER_DOWNLOADS_DIR.exists():
            self.watch_dirs.append(USER_DOWNLOADS_DIR)

        self.scanned_history = []
        self.scanned_files_map = {}  # file_path -> last_scanned_mtime
        self.is_watching = True      # Set to True for continuous scanning on startup
        self.scan_cycle_count = 0
        self.current_scanning_file = "Idle"
        self.sse_queues = []
        self._lock = threading.Lock()
        self.thread = None

    def register_sse_client(self) -> queue.Queue:
        q = queue.Queue()
        with self._lock:
            self.sse_queues.append(q)
        return q

    def unregister_sse_client(self, q: queue.Queue):
        with self._lock:
            if q in self.sse_queues:
                self.sse_queues.remove(q)

    def broadcast_scan_result(self, scan_result: dict):
        with self._lock:
            dead_queues = []
            for q in self.sse_queues:
                try:
                    q.put_nowait(scan_result)
                except Exception:
                    dead_queues.append(q)
            for q in dead_queues:
                self.sse_queues.remove(q)

    def start(self):
        self.is_watching = True
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._continuous_scan_loop, daemon=True, name="ContinuousScannerThread")
            self.thread.start()
        log_backend_message("SCANNER", f"Continuous File Scanner started. Actively monitoring {len(self.watch_dirs)} directories.", "INFO")

    def stop(self):
        self.is_watching = False
        self.current_scanning_file = "Stopped manually"
        log_backend_message("SCANNER", "Continuous File Scanner paused manually by user.", "WARN")

    def toggle(self) -> bool:
        if self.is_watching:
            self.stop()
        else:
            self.start()
        return self.is_watching

    def _continuous_scan_loop(self):
        """Continuously loops and scans all files in monitored folders until manually stopped."""
        while True:
            if not self.is_watching:
                time.sleep(0.5)
                continue

            self.scan_cycle_count += 1
            scanned_in_this_pass = 0

            for d in self.watch_dirs:
                if not d.exists() or not self.is_watching:
                    continue

                try:
                    # Scan all files in directory and first sub-level
                    entries = []
                    for root, dirs, files in os.walk(d):
                        # Avoid scanning deep into node_modules or system hidden dirs
                        dirs[:] = [sub for sub in dirs if not sub.startswith(".") and sub != "node_modules"]
                        for f in files:
                            entries.append(Path(root) / f)
                        # Limit to first 2 levels for speed and safety
                        if root.count(os.sep) - str(d).count(os.sep) >= 1:
                            del dirs[:]

                    for file_path in entries:
                        if not self.is_watching:
                            break

                        if not file_path.is_file():
                            continue

                        # Check extension
                        ext = file_path.suffix.lower()
                        if ext in [".tmp", ".crdownload", ".part", ".download"] or file_path.name.startswith("."):
                            continue

                        try:
                            st = file_path.stat()
                            mtime = st.st_mtime
                            size = st.st_size

                            # Check if file has already been scanned with same mtime & size in this pass
                            file_key = f"{file_path}_{mtime}_{size}"
                            last_scanned = self.scanned_files_map.get(file_key)

                            # Scan file
                            if last_scanned is None:
                                self.current_scanning_file = file_path.name
                                self.scan_file(file_path)
                                self.scanned_files_map[file_key] = time.time()
                                scanned_in_this_pass += 1
                                # Small yield so CPU remains responsive
                                time.sleep(0.05)
                        except Exception:
                            pass

                except Exception as e:
                    pass

            # Cycle completed
            self.current_scanning_file = "Watching for file changes & continuous pass..."
            
            # Short breather between full directory sweep cycles (1.5 seconds)
            for _ in range(15):
                if not self.is_watching:
                    break
                time.sleep(0.1)

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy (0.0 to 8.0). Values > 7.5 indicate encrypted ransomware payloads."""
        if not data:
            return 0.0
        length = len(data)
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return float(entropy)

    @staticmethod
    def format_bytes(size_bytes: int) -> str:
        if size_bytes == 0:
            return "0 Bytes"
        sizes = ["Bytes", "KB", "MB", "GB"]
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {sizes[i]}"

    def evaluate_heuristics(self, filename: str, ext: str, buffer: bytes, entropy: float, file_size: int) -> dict:
        risk_score = 0
        flags = []

        # Rule 1: Double Extension Trick (e.g. invoice.pdf.exe)
        parts = filename.split(".")
        if len(parts) > 2:
            second_last = parts[-2].lower()
            dangerous_exts = [".exe", ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".js", ".wsf", ".hta", ".pif"]
            doc_exts = ["pdf", "docx", "xlsx", "pptx", "jpg", "png", "txt", "zip", "csv"]
            if second_last in doc_exts and ext in dangerous_exts:
                risk_score += 45
                flags.append("CRITICAL: Double extension trick detected (masquerading document file)")

        # Rule 2: High Shannon Entropy (Ransomware / AES Encryption Payload)
        if entropy > 7.6:
            risk_score += 35
            flags.append("WARNING: Very high Shannon entropy (> 7.6) — indicates packed binary or AES ransomware payload")
        elif entropy > 7.2:
            risk_score += 15
            flags.append("INFO: Elevated entropy (> 7.2) — compressed data or compiled binary payload")

        # Rule 3: Portable Executable Header (MZ Header)
        is_pe_executable = len(buffer) > 2 and buffer[0:2] == b"MZ"
        if is_pe_executable:
            flags.append("INFO: Windows Portable Executable (PE) binary header verified")
            if ext not in [".exe", ".dll", ".sys", ".scr"]:
                risk_score += 40
                flags.append(f"CRITICAL: Binary executable disguised under non-executable extension ({ext})")
            else:
                risk_score += 15

        # Rule 4: Suspicious Command Strings & Ransomware Signatures
        content_sample = buffer[:64 * 1024].lower()
        suspicious_keywords = [
            b"cmd.exe /c", b"powershell -enc", b"powershell -encodedcommand",
            b"vssadmin delete shadows", b"wbadmin delete catalog",
            b"bcdedit /set", b"wscript.shell", b"net stop", b"cryptoapi",
            b"encrypt", b"ransom", b"bitcoin", b"torbrowser", b"bypass -command"
        ]

        found_keywords = []
        for kw in suspicious_keywords:
            if kw in content_sample:
                found_keywords.append(kw.decode(errors="ignore"))
                flags.append(f'SUSPICIOUS KEYWORD: Contains command pattern "{kw.decode(errors="ignore")}"')

        if found_keywords:
            risk_score += min(len(found_keywords) * 20, 50)

        # Rule 5: Zero-Byte / Corrupted File
        if file_size == 0:
            flags.append("INFO: Zero-byte file detected")

        # Classification
        if risk_score >= 65:
            threat_level = "MALICIOUS_RANSOMWARE_RISK"
        elif risk_score >= 30:
            threat_level = "SUSPICIOUS"
        else:
            threat_level = "CLEAN"

        return {
            "riskScore": min(risk_score, 100),
            "threatLevel": threat_level,
            "flags": flags,
            "isPEExecutable": is_pe_executable
        }

    def quarantine_file(self, file_path: Path, filename: str) -> bool:
        try:
            timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_path = QUARANTINE_DIR / f"{timestamp_prefix}_QUARANTINED_{filename}"
            for _ in range(5):
                try:
                    file_path.rename(dest_path)
                    log_backend_message("QUARANTINE", f"🔒 Isolated malicious threat '{filename}' -> {dest_path.name}", "WARN")
                    return True
                except PermissionError:
                    time.sleep(0.3)
            return False
        except Exception as e:
            log_backend_message("QUARANTINE", f"Failed to quarantine {filename}: {e}", "ERROR")
            return False

    def scan_file(self, file_path: Path) -> dict:
        filename = file_path.name
        ext = file_path.suffix.lower()

        if ext in [".tmp", ".crdownload", ".part", ".download"] or filename.startswith("."):
            return None

        try:
            if not file_path.exists():
                return None
            
            st = file_path.stat()
            file_size = st.st_size

            read_size = min(file_size, 10 * 1024 * 1024)
            with open(file_path, "rb") as f:
                buffer = f.read(read_size)

            entropy = round(self.calculate_shannon_entropy(buffer), 3)
            sha256_hash = hashlib.sha256(buffer).hexdigest()
            heuristics = self.evaluate_heuristics(filename, ext, buffer, entropy, file_size)

            scan_result = {
                "id": f"scan_{int(time.time()*1000)}_{os.urandom(3).hex()}",
                "timestamp": datetime.now().isoformat(),
                "filePath": str(file_path),
                "filename": filename,
                "extension": ext,
                "fileSize": file_size,
                "fileSizeFormatted": self.format_bytes(file_size),
                "sha256": sha256_hash,
                "entropy": entropy,
                "heuristics": heuristics,
                "threatLevel": heuristics["threatLevel"],
                "riskScore": heuristics["riskScore"],
                "quarantined": False
            }

            if heuristics["threatLevel"] == "MALICIOUS_RANSOMWARE_RISK":
                scan_result["quarantined"] = self.quarantine_file(file_path, filename)

            with self._lock:
                # Deduplicate history: if same file already exists in history, replace it with latest scan
                self.scanned_history = [s for s in self.scanned_history if s.get("filePath") != str(file_path)]
                self.scanned_history.insert(0, scan_result)
                if len(self.scanned_history) > 300:
                    self.scanned_history.pop()

            log_type = "INFO" if scan_result["threatLevel"] == "CLEAN" else ("WARN" if scan_result["threatLevel"] == "SUSPICIOUS" else "ERROR")
            log_msg = f"🛡️ Scanned '{filename}' ({scan_result['fileSizeFormatted']}) | Entropy: {entropy} | Threat: {scan_result['threatLevel']} (Risk: {scan_result['riskScore']}/100) | SHA-256: {sha256_hash[:12]}..."
            log_backend_message("SCANNER", log_msg, log_type)

            self.broadcast_scan_result(scan_result)
            return scan_result
        except Exception as e:
            return None


watcher = FileSecurityWatcher()
watcher.start()


# ============================================================================
# NATIVE LOCAL IPC / REST API SERVER
# ============================================================================
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class RansomSenseHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        pathname = parsed.path

        # 1. API: Scanner Status
        if pathname == "/api/scanner/status":
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "success": True,
                "isWatching": watcher.is_watching,
                "continuousScanning": watcher.is_watching,
                "currentFile": watcher.current_scanning_file,
                "cycleCount": watcher.scan_cycle_count,
                "monitoredDirectories": [str(d) for d in watcher.watch_dirs],
                "totalScanned": len(watcher.scanned_history),
                "quarantineDir": str(QUARANTINE_DIR)
            }
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        # 2. API: Scanner History
        if pathname == "/api/scanner/history":
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            with watcher._lock:
                history_copy = list(watcher.scanned_history)
            self.wfile.write(json.dumps({"success": True, "history": history_copy}).encode("utf-8"))
            return

        # 3. API: Real-Time SSE Stream
        if pathname == "/api/scanner/stream":
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            client_q = watcher.register_sse_client()
            try:
                self.wfile.write(b"retry: 3000\n\n")
                self.wfile.flush()
                while True:
                    try:
                        scan_item = client_q.get(timeout=20)
                        data_str = f"data: {json.dumps(scan_item)}\n\n"
                        self.wfile.write(data_str.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
            except Exception:
                pass
            finally:
                watcher.unregister_sse_client(client_q)
            return

        # 4. API: Read Server Logs
        if pathname == "/api/logs":
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "text/plain; charset=UTF-8")
            self.end_headers()
            if SERVER_LOG_FILE.exists():
                try:
                    content = SERVER_LOG_FILE.read_text(encoding="utf-8")
                    self.wfile.write(content.encode("utf-8"))
                except Exception as e:
                    self.wfile.write(f"[ERROR reading logs: {e}]".encode("utf-8"))
            else:
                self.wfile.write(b"[INFO] Server log file is empty.\n")
            return

        # 5. API: Quarantine List
        if pathname == "/api/quarantine/list":
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                items = []
                for p in QUARANTINE_DIR.iterdir():
                    if p.is_file():
                        st = p.stat()
                        items.append({
                            "name": p.name,
                            "size": watcher.format_bytes(st.st_size),
                            "modified": datetime.fromtimestamp(st.st_mtime).isoformat()
                        })
                self.wfile.write(json.dumps({"success": True, "items": items}).encode("utf-8"))
            except Exception as e:
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
            return

        self.send_response(200)
        self.send_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "RANSOM SENSE Backend Engine Active", "port": PORT}).encode("utf-8"))

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        pathname = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length)
        body_json = {}
        if body_bytes:
            try:
                body_json = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                pass

        # 1. API: Toggle or Control Continuous Scanning
        if pathname == "/api/scanner/toggle":
            new_state = watcher.toggle()
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "isWatching": new_state}).encode("utf-8"))
            return

        if pathname == "/api/scanner/start":
            watcher.start()
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "isWatching": True}).encode("utf-8"))
            return

        if pathname == "/api/scanner/stop":
            watcher.stop()
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "isWatching": False}).encode("utf-8"))
            return

        # 2. API: Reset Scanned Cache / Rescan All Now
        if pathname == "/api/scanner/rescan-all":
            watcher.scanned_files_map.clear()
            watcher.start()
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Rescanning all files..."}).encode("utf-8"))
            return

        # 3. API: Simulate Threat File
        if pathname == "/api/scanner/simulate":
            sim_type = body_json.get("type", "clean")
            timestamp_ms = int(time.time() * 1000)

            if sim_type == "ransomware":
                filename = f"urgent_invoice_document_{timestamp_ms}.pdf.exe"
                file_content = os.urandom(50 * 1024)
            elif sim_type == "suspicious":
                filename = f"financial_statement_{timestamp_ms}.docx"
                file_content = b"AutoOpen macro execution: Powershell.exe -ExecutionPolicy Bypass -Command " + os.urandom(512).hex().encode("utf-8")
            else:
                filename = f"annual_report_{timestamp_ms}.pdf"
                file_content = b"%PDF-1.5\nClean corporate annual report document text payload\n%%EOF"

            file_path = LOCAL_MONITORED_DIR / filename
            try:
                file_path.write_bytes(file_content)
                log_backend_message("SIMULATOR", f"⚡ Created test payload '{filename}' in ./monitored_downloads", "INFO")
                self.send_response(200)
                self.send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "filename": filename, "filePath": str(file_path)}).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
            return

        # 4. API: Scan File Now
        if pathname == "/api/scanner/scan-now":
            file_path_str = body_json.get("filePath")
            if not file_path_str or not os.path.exists(file_path_str):
                self.send_response(400)
                self.send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "File path does not exist"}).encode("utf-8"))
                return

            result = watcher.scan_file(Path(file_path_str))
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "scanResult": result}).encode("utf-8"))
            return

        # 5. API: Save Log Entry
        if pathname == "/api/logs":
            timestamp = body_json.get("timestamp", datetime.now().isoformat())
            source = body_json.get("source", "FRONTEND_GUI")
            log_type = body_json.get("type", "info").upper()
            msg = body_json.get("msg", "")

            log_backend_message(source, msg, log_type)

            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "timestamp": timestamp}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        pathname = parsed.path

        if pathname == "/api/logs":
            try:
                if SERVER_LOG_FILE.exists():
                    SERVER_LOG_FILE.write_text("", encoding="utf-8")
                if SERVER_JSONL_FILE.exists():
                    SERVER_JSONL_FILE.write_text("", encoding="utf-8")
                log_backend_message("SYSTEM", "Cleared server log files.", "WARN")
                self.send_response(200)
                self.send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": "Logs cleared"}).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def start_server():
    print_banner()
    server = ThreadedHTTPServer(("127.0.0.1", PORT), RansomSenseHandler)
    log_backend_message("SERVER", f"Ransom Sense Backend Service ready on 127.0.0.1:{PORT}", "INFO")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Ransom Sense Backend Engine...")
        watcher.is_watching = False
        server.server_close()
        print("Backend Service stopped cleanly.")

if __name__ == "__main__":
    start_server()
