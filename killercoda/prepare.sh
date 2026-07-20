#!/usr/bin/env bash
# Killercoda background prep: clone the project so the user starts ready-to-go.
# Runs once when the scenario boots. Output is not shown to the user.
set -e

# Source repo (a monorepo of DevOps projects). Override REPO_URL to fork it.
REPO_URL="${REPO_URL:-https://github.com/techiescamp/devops-projects.git}"
CLONE_DIR="${CLONE_DIR:-/root/devops-projects}"
# Stable path the scenario steps use, regardless of where the project sits
# inside the monorepo.
LINK="${LINK:-/root/nxos-compliance}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || true
apt-get install -y -qq git python3 python3-venv python3-pip >/dev/null 2>&1 || true

if [ ! -d "$CLONE_DIR/.git" ]; then
  git clone --depth 1 "$REPO_URL" "$CLONE_DIR" >/dev/null 2>&1 || true
fi

# Locate the project inside the monorepo by finding the checker source, so the
# scenario keeps working no matter which subdirectory it lives in.
PROJECT_DIR=""
if [ -n "${PROJECT_SUBDIR:-}" ] && [ -d "$CLONE_DIR/$PROJECT_SUBDIR" ]; then
  PROJECT_DIR="$CLONE_DIR/$PROJECT_SUBDIR"
else
  hit="$(find "$CLONE_DIR" -type f -name nxos_compliance_checker.py 2>/dev/null | head -1 || true)"
  # project root is the parent of src/
  [ -n "$hit" ] && PROJECT_DIR="$(dirname "$(dirname "$hit")")"
fi
# Fallback: the repo root itself.
[ -z "$PROJECT_DIR" ] && PROJECT_DIR="$CLONE_DIR"

ln -sfn "$PROJECT_DIR" "$LINK"

# Pre-create the venv + deps so step 1 is fast.
if [ -f "$LINK/requirements.txt" ]; then
  cd "$LINK"
  python3 -m venv .venv >/dev/null 2>&1 || true
  ./.venv/bin/pip install --quiet -r requirements.txt >/dev/null 2>&1 || true
fi

echo "done" > /tmp/prepare.done
