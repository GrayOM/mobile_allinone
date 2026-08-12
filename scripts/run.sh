#!/usr/bin/env bash
# Mobile Security Workbench를 Linux/macOS에서 안전한 loopback 기본값으로 실행한다.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENV_DIR="${MSW_VENV_DIR:-$ROOT_DIR/.venv}"
HOST="${MSW_HOST:-127.0.0.1}"
PORT="${MSW_PORT:-8765}"
INSTALL=false
SKIP_FRONTEND=false

usage() {
  cat <<'EOF'
Usage: ./scripts/run.sh [--install] [--skip-frontend] [--host HOST] [--port PORT]

  --install         Create/update the Python virtual environment and frontend dependencies.
  --skip-frontend   Do not rebuild the production frontend bundle.
  --host HOST       Server bind address. Default: 127.0.0.1.
  --port PORT       Server port. Default: 8765.

The default loopback bind is intentional. Do not expose this diagnostics workbench
on a LAN without setting MSW_LAN_ACCESS=true and strong MSW_API_TOKEN and
MSW_ADMIN_TOKEN values in .env.
EOF
}

while (($#)); do
  case "$1" in
    --install) INSTALL=true ;;
    --skip-frontend) SKIP_FRONTEND=true ;;
    --host)
      [[ $# -ge 2 ]] || { echo "--host requires a value." >&2; exit 2; }
      HOST="$2"; shift ;;
    --port)
      [[ $# -ge 2 ]] || { echo "--port requires a value." >&2; exit 2; }
      PORT="$2"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    echo "$2" >&2
    exit 1
  }
}

require_command python3 "Install Python 3.12, then run this command again."
require_command node "Install Node.js LTS, then run this command again."
require_command npm "Install Node.js LTS (including npm), then run this command again."

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$PYTHON_VERSION" != "3.12" ]]; then
  echo "Python 3.12 is required; found Python $PYTHON_VERSION." >&2
  echo "Use python3.12 or set MSW_VENV_DIR after creating a Python 3.12 virtual environment." >&2
  exit 1
fi

cd "$ROOT_DIR"
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "Creating Python virtual environment: $VENV_DIR"
  python3 -m venv "$VENV_DIR"
  INSTALL=true
fi

if [[ "$INSTALL" == true ]]; then
  echo "Installing Python dependencies…"
  "$VENV_DIR/bin/python" -m pip install --upgrade pip
  "$VENV_DIR/bin/python" -m pip install -e ".[dev]"
fi

if [[ "$SKIP_FRONTEND" == false ]]; then
  if [[ ! -d frontend/node_modules || "$INSTALL" == true ]]; then
    echo "Installing frontend dependencies…"
    (cd frontend && npm ci)
  fi
  echo "Building frontend…"
  (cd frontend && npm run build)
fi

export MSW_HOST="$HOST"
export MSW_PORT="$PORT"
echo "Starting Mobile Security Workbench at http://$HOST:$PORT"
echo "Press Ctrl+C to stop."
exec "$VENV_DIR/bin/python" -m uvicorn backend.app.main:app --host "$HOST" --port "$PORT"
