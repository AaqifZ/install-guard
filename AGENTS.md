# Install Guard: notes for coding agents

Install Guard keeps npm, pip and uv install protections on (no install-time code, a 7-day wait) and keeps agents moving.

## Layout
- `install_guard.py`: the hook for Claude Code and Codex. npm rules live here.
- `pyguard.py`: pip and uv rules. `install_guard.py` loads it on demand.
- `check.py`: the fire drill. `--fix` repairs drift first.
- `install.sh`, `launchd/`: the installer and the optional daily launch agent.
- `tests/`: rule tests, attack replays, and the fake npm registry and PyPI index they use.

## Build and test
Python 3.9+ standard library only. Nothing to build. Run from the repo root:

1. `python3 tests/test_rules.py` (offline, must print all passed)
2. `python3 tests/replay_axios.py` (needs npm 11.10+)
3. `python3 tests/replay_python.py` (needs pip 26.1+ and uv)

## Rules
- Deterministic rules only. No AI and no questions to the user in the hook path.
- Every deny must hand the agent a working next command.
- Uncertain or broken cases allow, and the log records them.
- Tests must never install into a real environment or change real config.
- Never weaken `~/.npmrc`, `pip.conf` or `uv.toml` to unblock an install.
