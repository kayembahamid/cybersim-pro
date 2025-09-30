#!/bin/sh
set -e

MODE="${CYBERSIM_MODE:-stdio}"

if [ "$MODE" = "http" ]; then
  exec node build/httpServer.js
else
  exec node build/index.js
fi

