# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for LogWatcher desktop app.

Build with:
    pyinstaller logwatcher.spec

Output: dist/LogWatcher   (folder mode)
        dist/LogWatcher/LogWatcher   (executable)
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH)  # noqa: F821  (SPECPATH is injected by PyInstaller)

# ── Data files ────────────────────────────────────────────────────────────────
datas = [
    # HTML templates and static assets
    (str(ROOT / "src" / "templates"), "src/templates"),
    (str(ROOT / "src" / "static"),    "src/static"),
]

# Include pywebview's own data (platform renderer assets)
datas += collect_data_files("webview")

# ── Hidden imports ────────────────────────────────────────────────────────────
hiddenimports = [
    # FastAPI / Starlette internals not always auto-detected
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "starlette.routing",
    "starlette.staticfiles",
    "starlette.templating",
    "jinja2",
    "multipart",
    # pywebview platform backends (Linux uses gtk or qt)
    "webview.platforms.gtk",
    "webview.platforms.qt",
    "webview.platforms.cocoa",   # macOS
    "webview.platforms.winforms", # Windows
    # scikit-learn tree / estimator internals
    *collect_submodules("sklearn"),
    # Other app modules
    "src.webapp",
    "src.analyzer",
    "src.charts",
    "src.cli",
    "src.dataset_loader",
    "src.eval",
    "src.generator",
    "src.llm_adapter",
    "src.mitre_mapping",
    "src.parsers",
    "src.pipeline",
    "src.structurizer",
    "src.translator",
    "src.desktop",
]

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(  # noqa: F821
    [str(ROOT / "run_desktop.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib.tests", "numpy.testing"],
    noarchive=False,
)

pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="LogWatcher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # no terminal window on launch
    icon=None,              # add an .ico/.icns path here if you have one
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="LogWatcher",
)
