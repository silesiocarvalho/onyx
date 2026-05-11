#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# start.sh — Launch Sariel inside a uv venv
#
# First run:  bash start.sh          (installs deps + starts server)
# Later runs: bash start.sh          (reuses existing venv)
# Dev mode:   uv run uvicorn backend.main:app --reload
# ─────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# ── 0. Load local environment overrides ─────────────────────
if [ -f "$PROJECT_DIR/.env" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$PROJECT_DIR/.env"
  set +a
  echo "  [✓] Loaded .env"
fi

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  Sariel — Firewall Security Assessment  ║"
echo "  ║  Gaia R82 · CIS Benchmark v1.1.0        ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# ── 1. Check uv is installed ────────────────────────────────
if ! command -v uv &>/dev/null; then
  echo "  ✗  'uv' not found."
  echo "     Install with:  curl -LsSf https://astral.sh/uv/install.sh | sh"
  echo "     Then restart your shell and run this script again."
  exit 1
fi

UV_VERSION=$(uv --version 2>&1)
echo "  [✓] $UV_VERSION"

# ── 2. Sync the virtual environment ─────────────────────────
echo "  [*] Syncing virtual environment (.venv/)..."
uv sync --quiet
echo "  [✓] Virtual environment ready."
echo ""

# ── 3. Show what's installed (brief) ────────────────────────
echo "  [*] Key packages:"
uv pip list 2>/dev/null | grep -E "fastapi|uvicorn|litellm|anthropic|paramiko|cryptography|reportlab|openpyxl" \
  | awk '{printf "      %-20s %s\n", $1, $2}' || true
echo ""

# ── 4. Start the server ─────────────────────────────────────
echo "  ┌─────────────────────────────────────────────┐"
echo "  │  Server starting...                         │"
echo "  │  Open:  http://localhost:8000               │"
echo "  │                                             │"
echo "  │  Press Ctrl+C to stop                      │"
echo "  └─────────────────────────────────────────────┘"
echo ""

# Run uvicorn inside the uv-managed venv, from the project root
# so that 'backend.main' and 'tools.*' are importable as packages
uv run uvicorn backend.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --log-level warning
