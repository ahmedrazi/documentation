#!/usr/bin/env bash
# Re-run a compliance scan and refresh the dashboard data.
# Usage: ./run_scan.sh [config-dir]   (default: ./configs)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CONFIG_DIR="${1:-configs}"
PY="python3"
[[ -x "$ROOT/.venv/bin/python3" ]] && PY="$ROOT/.venv/bin/python3"

mkdir -p output
"$PY" src/nxos_compliance_checker.py \
  --config-dir "$CONFIG_DIR" \
  --policy policy/nxos_policy.yaml \
  --format console --no-color

"$PY" src/nxos_compliance_checker.py \
  --config-dir "$CONFIG_DIR" \
  --policy policy/nxos_policy.yaml \
  --format ndjson --output output/compliance.ndjson

cp -f output/compliance.ndjson dashboard/compliance.ndjson
echo "==> Refreshed output/compliance.ndjson (and dashboard copy)."
