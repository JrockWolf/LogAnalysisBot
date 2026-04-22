"""Desktop entry point for LogAnalysisBot.

Starts the FastAPI server in a background thread, waits for it to be ready,
then opens a pywebview window. When the window is closed the server is stopped.

Works on Linux (Qt or GTK), macOS (WebKit), and Windows (WebView2/WinForms).
Also compatible with PyInstaller frozen builds.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

import uvicorn
import webview


def _base_dir() -> Path:
    """Return the app's base directory, works both normally and when frozen."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # PyInstaller extracts files to sys._MEIPASS at runtime
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent

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
        # Use absolute import when frozen (no package __init__ in PyInstaller bundle)
        if getattr(sys, "frozen", False):
            from src.webapp import app as fastapi_app  # type: ignore[import]
        else:
            from .webapp import app as fastapi_app  # type: ignore[import]

        # Point Jinja2 templates and static files at the correct extracted path
        base = _base_dir()
        os.environ.setdefault("LOGWATCHER_TEMPLATES", str(base / "src" / "templates"))
        os.environ.setdefault("LOGWATCHER_STATIC", str(base / "src" / "static"))

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

    # Pick the best available GUI backend for the current platform
    gui: str | None = None
    if sys.platform == "linux":
        # Prefer Qt (pip-installable); fall back to GTK (system package)
        try:
            import qtpy  # noqa: F401
            gui = "qt"
        except ImportError:
            gui = "gtk"
    elif sys.platform == "darwin":
        gui = "cocoa"
    elif sys.platform == "win32":
        # Use EdgeChromium (WebView2) when available, else WinForms
        try:
            import clr  # pythonnet  # noqa: F401
            gui = "winforms"
        except ImportError:
            gui = "edgechromium"

    webview.start(gui=gui, debug=False)


if __name__ == "__main__":
    main()
