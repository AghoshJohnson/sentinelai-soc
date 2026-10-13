#!/usr/bin/env bash
# ============================================================
# AI SOC Assistant — CLI Launcher (Linux / macOS)
# ============================================================
# Usage:
#   ./run_cli.sh analyse data/samples/ssh_bruteforce.log
#   ./run_cli.sh analyse data/samples/sql_injection.log --type web --no-ai
#   ./run_cli.sh status
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate venv if present
if [[ -f "$SCRIPT_DIR/venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/venv/bin/activate"
elif [[ -f "$SCRIPT_DIR/.venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.venv/bin/activate"
fi

# Ensure outputs directory exists
mkdir -p outputs/reports

python -m app.cli "$@"
