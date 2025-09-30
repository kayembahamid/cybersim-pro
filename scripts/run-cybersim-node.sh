#!/usr/bin/env bash
set -euo pipefail

# Resolve project root (this script lives in /scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR%/scripts}"

ENTRY="${PROJECT_ROOT}/build/index.js"
if [[ ! -f "${ENTRY}" ]]; then
  echo "[cybersim-pro] Build output not found at ${ENTRY}." >&2
  echo "Run: (cd ${PROJECT_ROOT} && npm run build)" >&2
  exit 1
fi

exec node "${ENTRY}"

