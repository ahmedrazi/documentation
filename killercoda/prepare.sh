#!/usr/bin/env bash
# Killercoda background prep: clone the project so the user starts ready-to-go.
# Runs once when the scenario boots. Output is not shown to the user.
set -e

REPO_URL="${REPO_URL:-https://github.com/ahmedrazi/documentation.git}"
DEST="${DEST:-/root/documentation}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || true
apt-get install -y -qq git python3 python3-venv python3-pip >/dev/null 2>&1 || true

if [ ! -d "$DEST/.git" ]; then
  git clone --depth 1 "$REPO_URL" "$DEST" >/dev/null 2>&1 || true
fi

# Pre-create the venv + deps so step 1 is fast.
if [ -d "$DEST" ]; then
  cd "$DEST"
  python3 -m venv .venv >/dev/null 2>&1 || true
  ./.venv/bin/pip install --quiet -r requirements.txt >/dev/null 2>&1 || true
fi

echo "done" > /tmp/prepare.done
