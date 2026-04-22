# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for LogWatcher desktop app — Linux, macOS, Windows.

Build:
    pyinstaller logwatcher.spec

Outputs:
    Linux / Windows : dist/LogWatcher/LogWatcher(.exe)   (folder mode)
    macOS           : dist/LogWatcher.app                 (bundle)
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH)  # noqa: F821  (injected by PyInstaller)

IS_WINDOWS = sys.platform == "win32"
IS_MAC     = sys.platform == "darwin"
IS_LINUX   = sys.platform == "linux"

# ── Data files ────────────────────────────────────────────────────────────────
datas = [
    (str(ROOT / "src" / "templates"), "src/templates"),
    (str(ROOT / "src" / "static"),    "src/static"),
]
datas += collect_data_files("webview")

# ── Hidden imports ────────────────────────────────────────────────────────────
hiddenimports = [
    # uvicorn internals
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
    # Starlette / FastAPI
    "starlette.routing",
    "starlette.staticfiles",
    "starlette.templating",
    "jinja2",
    "multipart",
    # scikit-learn
    *collect_submodules("sklearn"),
    # app modules
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

# Platform-specific pywebview backends
if IS_LINUX:
    hiddenimports += ["webview.platforms.gtk", "webview.platforms.qt", "qtpy"]
elif IS_MAC:
    hiddenimports += ["webview.platforms.cocoa"]
    try:
        datas += collect_data_files("objc")
    except Exception:
        pass
elif IS_WINDOWS:
    hiddenimports += ["webview.platforms.winforms", "webview.platforms.edgechromium", "clr"]

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
    strip=not IS_WINDOWS,       # strip is unsupported on Windows
    upx=True,
    console=False,              # no terminal window on any platform
    # Provide platform-specific icons if available
    icon=str(ROOT / "assets" / "icon.ico")   if IS_WINDOWS and (ROOT / "assets" / "icon.ico").exists()   else
         str(ROOT / "assets" / "icon.icns")  if IS_MAC     and (ROOT / "assets" / "icon.icns").exists()  else
         str(ROOT / "assets" / "icon.png")   if IS_LINUX   and (ROOT / "assets" / "icon.png").exists()   else None,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=not IS_WINDOWS,
    upx=True,
    upx_exclude=[],
    name="LogWatcher",
)

# macOS: wrap in a proper .app bundle
if IS_MAC:
    app = BUNDLE(  # noqa: F821
        coll,
        name="LogWatcher.app",
        icon=str(ROOT / "assets" / "icon.icns") if (ROOT / "assets" / "icon.icns").exists() else None,
        bundle_identifier="online.logwatcher.app",
        info_plist={
            "CFBundleDisplayName": "LogWatcher",
            "CFBundleShortVersionString": "1.0.0",
            "NSHighResolutionCapable": True,
            "NSRequiresAquaSystemAppearance": False,  # support dark mode
        },
    )

