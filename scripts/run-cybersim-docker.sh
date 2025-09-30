#!/usr/bin/env bash
set -euo pipefail

IMAGE="${CYBERSIM_IMAGE:-cybersim-pro-mcp}"

exec docker run --rm -i "${IMAGE}"

