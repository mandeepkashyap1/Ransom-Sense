"""
RANSOM SENSE — Unified System Launcher
Launches both Native Desktop Programs (Backend Security Engine + Frontend SOC Monitor)
"""

import os
import sys
import subprocess
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def main():
    print("=" * 70)
    print("  RANSOM SENSE — 100% NATIVE PC SECURITY ARCHITECTURE")
    print("=" * 70)
    print("  [1] Starting Ransom Sense Backend Daemon (backend_server.py)...")
    
    if sys.platform == "win32":
        backend_proc = subprocess.Popen(
            [sys.executable, str(BASE_DIR / "backend_server.py")],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        backend_proc = subprocess.Popen(
            [sys.executable, str(BASE_DIR / "backend_server.py")]
        )

    time.sleep(1.2)

    print("  [2] Starting Ransom Sense Desktop GUI (frontend_app.py)...")
    frontend_proc = subprocess.Popen(
        [sys.executable, str(BASE_DIR / "frontend_app.py")]
    )

    print("\n  Both native programs are running locally on your PC:")
    print("  - Backend Console: Monitoring filesystem, Shannon entropy & auto-quarantine")
    print("  - Frontend GUI: Real-time threat stream, HUD counters, & Quarantine Vault")
    print("=" * 70)

    try:
        frontend_proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if backend_proc.poll() is None:
            backend_proc.terminate()

if __name__ == "__main__":
    main()
