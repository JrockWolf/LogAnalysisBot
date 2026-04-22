"""Desktop entry point for LogAnalysisBot.

Starts the FastAPI server in a background thread, waits for it to be ready,
then opens a pywebview window. When the window is closed the server is stopped.
"""

from __future__ import annotations

import socket
import sys
import threading
import time

import uvicorn
import webview

# ── Port selection ────────────────────────────────────────────────────────────

def _find_free_port(start: int = 18432) -> int:
    """Return the first free TCP port >= start."""
    port = start
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1


def _wait_for_server(host: str, port: int, timeout: float = 15.0) -> bool:
    """Block until the server accepts connections or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# ── Server thread ─────────────────────────────────────────────────────────────

class _ServerThread(threading.Thread):
    def __init__(self, host: str, port: int) -> None:
        super().__init__(daemon=True, name="uvicorn-server")
        self._host = host
        self._port = port
        self._server: uvicorn.Server | None = None

    def run(self) -> None:
        from .webapp import app as fastapi_app  # lazy import keeps startup fast

        config = uvicorn.Config(
            fastapi_app,
            host=self._host,
            port=self._port,
            log_level="warning",
            # Don't install signal handlers — the main thread owns those
            loop="asyncio",
        )
        self._server = uvicorn.Server(config)
        self._server.run()

    def stop(self) -> None:
        if self._server:
            self._server.should_exit = True


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    host = "127.0.0.1"
    port = _find_free_port()
    url = f"http://{host}:{port}"

    server = _ServerThread(host, port)
    server.start()

    if not _wait_for_server(host, port, timeout=20.0):
        print("ERROR: Server did not start in time.", file=sys.stderr)
        sys.exit(1)

    window = webview.create_window(
        title="LogWatcher — Log Analysis Bot",
        url=url,
        width=1280,
        height=860,
        resizable=True,
        min_size=(900, 600),
    )

    # Stop the server when the window is destroyed
    window.events.closed += server.stop

    webview.start(debug=False)


if __name__ == "__main__":
    main()
