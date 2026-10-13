#!/usr/bin/env bash
# ============================================================
# AI SOC Assistant — Streamlit GUI Launcher (Linux / macOS)
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -f "$SCRIPT_DIR/venv/bin/activate" ]]; then
    source "$SCRIPT_DIR/venv/bin/activate"
elif [[ -f "$SCRIPT_DIR/.venv/bin/activate" ]]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
fi

mkdir -p outputs/reports

echo ""
echo " ============================================================"
echo "  AI SOC Assistant — Starting Streamlit GUI"
echo "  Opening at: http://localhost:8501"
echo "  Press Ctrl+C to stop."
echo " ============================================================"
echo ""

streamlit run app/gui.py \
    --server.port 8501 \
    --server.headless false \
    --browser.gatherUsageStats false \
    --theme.base dark
