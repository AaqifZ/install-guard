#!/bin/bash
# Install the daily fire drill as a launch agent for the current user. Asks first.
# Usage: launchd/install.sh [--yes] [python]   (default python: python3 on PATH)
#
# What it changes:
#   - writes ~/Library/LaunchAgents/com.aaqifz.install-guard.plist (paths filled in for this checkout)
#   - loads it with launchctl, for your user only (no sudo)
# The agent runs `check.py --fix --quiet` at login and every day at 09:20. With --fix it may:
#   - upgrade npm to 11.20.0 (global npm, and the npm in each Homebrew node@* keg) if older than 11.10
#   - add ignore-scripts=true and min-release-age=7 to ~/.npmrc (backup: ~/.npmrc.bak-<date>)
#   - replace ~/.config/pip/pip.conf and ~/.config/uv/uv.toml if missing or weaker (backup: <file>.bak-<date>)
#   - add missing hook entries to ~/.claude/settings.json and ~/.codex/hooks.json (backup: <file>.bak-install-guard)
# Log: ~/Library/Logs/install-guard.log
# Remove: launchctl bootout gui/$(id -u)/com.aaqifz.install-guard, then delete the plist file.
set -euo pipefail
YES=0
if [[ "${1:-}" == "--yes" ]]; then YES=1; shift; fi
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${1:-$(command -v python3 || true)}"
[[ -n "$PYTHON" ]] || { echo "python3 not found. Pass a Python path as an argument." >&2; exit 1; }
LABEL=com.aaqifz.install-guard
DEST="$HOME/Library/LaunchAgents/$LABEL.plist"

if [[ $YES -ne 1 ]]; then
    echo "This loads a launch agent: $DEST"
    echo "At login and every day at 09:20 it runs: $PYTHON $REPO/check.py --fix --quiet"
    echo "--fix can upgrade npm and restore ~/.npmrc, pip.conf, uv.toml and the agent hooks (backups kept)."
    read -r -p "Load the launch agent? [y/N] " answer
    [[ "$answer" == [yY]* ]] || { echo "Skipped. Nothing changed."; exit 0; }
fi

mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
sed -e "s|__REPO__|$REPO|g" -e "s|__PYTHON__|$PYTHON|g" -e "s|__HOME__|$HOME|g" \
    "$REPO/launchd/$LABEL.plist" > "$DEST"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$DEST"
echo "Loaded $LABEL from $DEST"
