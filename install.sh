#!/bin/bash
# Install Guard installer for macOS. It shows each change and asks before it makes it.
# Usage: ./install.sh            (set INSTALL_GUARD_PYTHON to use a Python other than python3 on PATH)
set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${INSTALL_GUARD_PYTHON:-$(command -v python3 || true)}"

fail() { echo "install-guard: $*" >&2; exit 1; }
[[ "$(uname -s)" == Darwin ]] || fail "this installer is for macOS."
[[ -n "$PYTHON" ]] || fail "python3 not found. Install Python 3.9 or later (for example: brew install python)."
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 9))' || fail "$PYTHON is older than Python 3.9."
PIPV="$("$PYTHON" -m pip --version 2>/dev/null | awk '{print $2}')"
if ! "$PYTHON" -c 'import sys; v = tuple(int(x) for x in sys.argv[1].split(".")[:2]); sys.exit(v < (26, 1))' "${PIPV:-0.0}" 2>/dev/null; then
    echo "Warning: $PYTHON has pip ${PIPV:-(none)}. pip before 26.1 ignores the 7-day wait (wheels-only still works)."
    echo "         Use Homebrew Python (brew install python), or set INSTALL_GUARD_PYTHON to a Python with pip 26.1+."
fi
command -v npm >/dev/null || fail "npm not found. Install Node.js first (for example: brew install node)."
[[ -d "$HOME/.claude" || -d "$HOME/.codex" ]] || echo "Note: no ~/.claude or ~/.codex found, so no agent hooks will be added."
export INSTALL_GUARD_PYTHON="$PYTHON"

cat <<EOF

Install Guard will make these changes for your user (no sudo):

  1. npm: if a version is older than 11.10, upgrade it to 11.20.0
     (the npm on PATH, and the npm in each Homebrew node@* keg).
  2. ~/.npmrc: set ignore-scripts=true and min-release-age=7. Other lines stay.
     Backup: ~/.npmrc.bak-<date>
  3. ~/.config/pip/pip.conf and ~/.config/uv/uv.toml: if missing or weaker, replace
     them with wheels-only and a 7-day wait. Backup: <file>.bak-<date>
  4. ~/.claude/settings.json: add 4 hook entries (PreToolUse, PostToolUse,
     PostToolUseFailure, SessionStart). ~/.codex/hooks.json: add 1 PreToolUse entry.
     Only for the tools you have. Backup: <file>.bak-install-guard
     Each hook runs: $PYTHON $REPO/install_guard.py

Then it runs the fire drill: a harmless replay of the Axios attack against your config.

EOF
read -r -p "Make these changes? [y/N] " answer
[[ "$answer" == [yY]* ]] || { echo "Nothing changed."; exit 0; }

"$PYTHON" "$REPO/check.py" --fix || echo "The drill reported a problem. Read the FAIL lines above."

echo
echo "Optional: a launch agent runs the same check with --fix at login and every day at 09:20."
read -r -p "Load the launch agent too? [y/N] " answer
if [[ "$answer" == [yY]* ]]; then
    "$REPO/launchd/install.sh" --yes "$PYTHON"
else
    echo "Skipped. Run launchd/install.sh later to add it."
fi
echo
echo "Done. Check any time with: $PYTHON $REPO/install_guard.py --doctor"
