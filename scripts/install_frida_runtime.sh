#!/usr/bin/env bash
# Install the pinned Frida 17+ runtime bridges used by the workbench loader.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME="$ROOT/scripts/frida/runtime"
if ! command -v npm >/dev/null 2>&1; then
  echo "npm이 필요합니다. Node.js 18 이상을 설치하세요." >&2
  exit 1
fi
cd "$RUNTIME"
npm install --no-audit --no-fund --ignore-scripts --save-exact
echo "Frida runtime bridges installed in $RUNTIME/node_modules"
