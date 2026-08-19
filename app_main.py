"""
RANSOM SENSE — Standalone Unified Application Entrypoint
Integrates the Backend Security Engine Daemon and Frontend SOC GUI into a single executable.
"""

import sys
import threading
import time
import backend_server
import frontend_app

def main():
    # 1. Start Backend Security Engine in Background Thread
    backend_thread = threading.Thread(
        target=backend_server.start_server,
        daemon=True,
        name="RansomSenseBackendThread"
    )
    backend_thread.start()

    # Allow backend server to bind socket
    time.sleep(0.8)

    # 2. Start Frontend SOC GUI in Main Thread
    app = frontend_app.RansomSenseFrontend()
    app.mainloop()

if __name__ == "__main__":
    main()
