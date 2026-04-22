#!/usr/bin/env bash
# Launch LogWatcher desktop app using the project virtualenv.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"

if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "ERROR: virtualenv not found at $VENV_PYTHON"
    echo "Run: python -m venv .venv && pip install -r requirements.txt"
    exit 1
fi

exec "$VENV_PYTHON" "$SCRIPT_DIR/run_desktop.py" "$@"
