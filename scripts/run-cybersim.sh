#!/usr/bin/env bash
set -euo pipefail

# Resolve project root (this script lives in /scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR%/scripts}"

# Choose runtime: node (default) or docker
RUNTIME="${CYBERSIM_RUNTIME:-node}"

if [[ "${RUNTIME}" == "docker" ]]; then
  IMAGE="${CYBERSIM_IMAGE:-cybersim-pro-mcp}"
  exec docker run --rm -i "${IMAGE}"
else
  exec node "${PROJECT_ROOT}/build/index.js"
fi

