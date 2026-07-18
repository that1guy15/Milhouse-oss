#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "Setting up Milhouse OSS starter repo..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
else
  echo ".env already exists; leaving it untouched"
fi

if [ ! -f "config/milhouse.toml" ]; then
  cp config/example.toml config/milhouse.toml
  echo "Created config/milhouse.toml from config/example.toml"
else
  echo "config/milhouse.toml already exists; leaving it untouched"
fi

mkdir -p data/state spool logs reports/generated

echo
echo "Next steps:"
echo "  1. Edit .env and config/milhouse.toml"
echo "  2. Start local ClickHouse when core code is added"
echo "  3. Run: make test"
echo "  4. Connect agents with .mcp.example.json after MCP server implementation lands"
