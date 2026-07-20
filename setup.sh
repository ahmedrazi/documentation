#!/usr/bin/env bash
# =============================================================================
# setup.sh -- native single-box bootstrap for the NX-OS Compliance Checker.
#
# Targets a plain Ubuntu box (e.g. Killercoda). No Docker required.
# Installs Python + PyYAML into a local virtualenv, runs an initial scan, and
# prints how to view the dashboard.
#
#   ./setup.sh            # install deps, run a scan, show next steps
#   ./setup.sh --serve    # ... and start the dashboard server in the foreground
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv"
PORT="${PORT:-8000}"
SERVE=0
[[ "${1:-}" == "--serve" ]] && SERVE=1

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# --- Python -----------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  log "Installing python3 (needs sudo/apt)..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-venv python3-pip
  else
    echo "python3 not found and apt-get unavailable; install Python 3 manually." >&2
    exit 1
  fi
fi

# --- virtualenv + deps ------------------------------------------------------
if [[ ! -d "$VENV" ]]; then
  log "Creating virtualenv at .venv ..."
  python3 -m venv "$VENV" 2>/dev/null || {
    log "python3-venv missing; installing..."
    sudo apt-get install -y -qq python3-venv
    python3 -m venv "$VENV"
  }
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
log "Installing dependencies (PyYAML) ..."
pip install --quiet --disable-pip-version-check -r requirements.txt

# --- initial scan -----------------------------------------------------------
mkdir -p output
log "Running initial compliance scan over ./configs ..."
python3 src/nxos_compliance_checker.py \
  --config-dir configs \
  --policy policy/nxos_policy.yaml \
  --format console --no-color || true

log "Writing NDJSON for the dashboard/Splunk ..."
python3 src/nxos_compliance_checker.py \
  --config-dir configs \
  --policy policy/nxos_policy.yaml \
  --format ndjson --output output/compliance.ndjson

# Make the NDJSON reachable from the dashboard folder for the static server.
cp -f output/compliance.ndjson dashboard/compliance.ndjson

echo
log "Setup complete."
echo "   Dashboard : cd dashboard && python3 -m http.server ${PORT}   ->  http://localhost:${PORT}"
echo "   Re-scan   : make scan   (or ./run_scan.sh)"
echo "   Splunk    : docker compose --profile splunk up -d   (optional, needs Docker)"

if [[ "$SERVE" == "1" ]]; then
  echo
  log "Serving dashboard on http://0.0.0.0:${PORT} (Ctrl-C to stop) ..."
  cd dashboard && exec python3 -m http.server "$PORT"
fi
