#!/usr/bin/env bash
# Launch LogAnalysisBot — desktop mode preferred, web mode fallback
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 1. Try the .venv312 desktop venv first ───────────────────────────────────
if [[ -x "$SCRIPT_DIR/.venv312/bin/python" ]]; then
    echo "[launch] Using .venv312 (Python 3.12 desktop venv)"
    exec "$SCRIPT_DIR/.venv312/bin/python" "$SCRIPT_DIR/run_desktop.py" "$@"
fi

# ── 2. Search for a compatible Python (3.9 through 3.12) ────────────────────
COMPAT_PYTHON=""
for VER in 3.12 3.11 3.10 3.9; do
    if command -v "python$VER" &>/dev/null; then
        COMPAT_PYTHON="python$VER"
        break
    fi
done

# Also accept a plain 'python3' or 'python' if version is in range
if [[ -z "$COMPAT_PYTHON" ]]; then
    for CMD in python3 python; do
        if command -v "$CMD" &>/dev/null; then
            VER=$("$CMD" -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>/dev/null || echo "0.0")
            MAJOR="${VER%%.*}"
            MINOR="${VER#*.}"
            if [[ "$MAJOR" -eq 3 && "$MINOR" -ge 9 && "$MINOR" -le 12 ]]; then
                COMPAT_PYTHON="$CMD"
                break
            fi
        fi
    done
fi

if [[ -n "$COMPAT_PYTHON" ]]; then
    echo "[launch] Found compatible Python: $($COMPAT_PYTHON --version)"
    if [[ ! -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
        echo "[launch] Creating virtualenv ..."
        "$COMPAT_PYTHON" -m venv "$SCRIPT_DIR/.venv"
        "$SCRIPT_DIR/.venv/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements-desktop.txt"
    fi
    exec "$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/run_desktop.py" "$@"
fi

# ── 3. Fall back to any Python (web-only mode) ───────────────────────────────
FALLBACK=""
for CMD in python3 python; do
    if command -v "$CMD" &>/dev/null; then
        FALLBACK="$CMD"
        break
    fi
done

if [[ -n "$FALLBACK" ]]; then
    echo "[launch] WARNING: Desktop deps unavailable in this environment."
    echo "[launch] Falling back to web mode at http://localhost:8000"
    if [[ ! -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
        "$FALLBACK" -m venv "$SCRIPT_DIR/.venv"
        "$SCRIPT_DIR/.venv/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
    fi
    exec "$SCRIPT_DIR/.venv/bin/python" -m uvicorn src.webapp:app --host 127.0.0.1 --port 8000
fi

echo "ERROR: No Python installation found."
echo "Install Python from https://www.python.org/downloads/"
exit 1

