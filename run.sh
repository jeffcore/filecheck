#!/usr/bin/env bash
# Usage: ./run.sh            -> scan everything in ./to-check
#        ./run.sh --rebuild  -> rebuild image first (refreshes virus signatures)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p to-check checked
if [[ "${1:-}" == "--rebuild" ]]; then docker compose build --no-cache; else docker compose build -q; fi
docker compose run --rm scanner
