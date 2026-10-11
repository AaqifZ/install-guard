#!/usr/bin/env python3
"""Daily fire drill for Install Guard. Proves the protection works on this machine, and repairs drift.

It replays the attack for real, with harmless fakes, against the real npm, pip and uv config:
  1. npm installs axios from a fake registry -> must get 1.14.0, and no payload runs.
  2. pip and uv install requestz from a fake index -> must get 2.31.0, and no payload runs.
  3. The hook must refuse an agent that switches a protection off.
  4. The hooks must be present in Claude Code and Codex.
With --fix it first repairs safe drift: npm too old, a config file missing or weakened, a hook missing.
Each file it rewrites is backed up first. Without --fix it changes nothing outside temp folders and its cache.
Writes ~/.cache/install-guard/status.json. The SessionStart hook reads it. Stdlib only.

INSTALL_GUARD_PYTHON picks the Python for the hooks and the pip drill (default: python3 on PATH).

Usage: check.py [--fix] [--quiet]
"""
import datetime
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import install_guard  # noqa: E402

HOME = pathlib.Path.home()
STATUS = install_guard.STATE / "status.json"
NPM_GOOD = "11.20.0"
PY = os.environ.get("INSTALL_GUARD_PYTHON") or shutil.which("python3") or sys.executable
HOOK = f"{shlex.quote(PY)} {shlex.quote(str(ROOT / 'install_guard.py'))}"
CODEX_HOOK = HOOK + " --host=codex"
CLAUDE_DIR, CODEX_DIR = HOME / ".claude", HOME / ".codex"
PIP_CONF = HOME / ".config" / "pip" / "pip.conf"
UV_TOML = HOME / ".config" / "uv" / "uv.toml"
PIP_TEXT = ("# Install protection (Install Guard). Wheels only, nothing younger than 7 days.\n"
            "[global]\nonly-binary = :all:\n\n[install]\nuploaded-prior-to = P7D\n")
UV_TEXT = '# Install protection (Install Guard).\nexclude-newer = "7 days"\n\n[pip]\nonly-binary = [":all:"]\n'


def run(cmd, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=kw.pop("timeout", 300), **kw)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")


def backup(path, suffix):
    """Copy a file to <name><suffix> before the first change. Keeps an existing backup."""
    target = path.with_name(path.name + suffix)
    if path.exists() and not target.exists():
        shutil.copy(path, target)


# ---------- repair ----------

def heal():
    """Fix safe, known drift. Returns a list of what was fixed."""
    fixed = []
    v = install_guard.npm_version()
    npm = shutil.which("npm")
    if npm and (v is None or v < install_guard.MIN_NPM):
        if run([npm, "install", "-g", f"npm@{NPM_GOOD}", "--no-audit", "--no-fund"]).returncode == 0:
            fixed.append(f"npm {'.'.join(map(str, v)) if v else '?'} -> {NPM_GOOD}")
    # Homebrew Node kegs ship their own npm, and brew upgrades put npm 10 back. Install into the keg itself:
    # its global prefix is the Homebrew prefix, so a plain `npm install -g` would hit the main npm instead.
    for keg_npm in (install_guard.keg_npms() if npm else []):
        kv = install_guard.npm_version(keg_npm)
        if kv is None or kv < install_guard.MIN_NPM:
            keg = str(pathlib.Path(keg_npm).parent.parent)
            if run([npm, "install", "-g", f"npm@{NPM_GOOD}",
                    "--prefix", keg, "--no-audit", "--no-fund"]).returncode == 0:
                fixed.append(f"{keg_npm} {'.'.join(map(str, kv)) if kv else '?'} -> {NPM_GOOD}")
    npmrc = HOME / ".npmrc"
    text = npmrc.read_text() if npmrc.exists() else ""
    add = []
    if not any(l.strip() == "ignore-scripts=true" for l in text.splitlines()):
        add.append("ignore-scripts=true")
    if install_guard.cooldown_days() < 7 or "min-release-age" not in text:
        add.append("min-release-age=7")
    if add:
        backup(npmrc, f".bak-{datetime.date.today()}")
        lines = [l for l in text.splitlines() if not l.strip().startswith(("ignore-scripts", "min-release-age"))]
        npmrc.write_text("\n".join(lines + ["ignore-scripts=true", "min-release-age=7"]) + "\n")
        fixed.append("~/.npmrc protections restored")
    import pyguard
    for path, good in ((PIP_CONF, PIP_TEXT), (UV_TOML, UV_TEXT)):
        rows_ok = path.exists() and not pyguard.weak_config_text(path.read_text(), 7) and (
            ("only-binary = :all:" in path.read_text() and "uploaded-prior-to" in path.read_text()) if path == PIP_CONF
            else ("exclude-newer" in path.read_text() and ":all:" in path.read_text()))
        if not rows_ok:
            backup(path, f".bak-{datetime.date.today()}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(good)
            fixed.append(f"{path.name} restored")
    fixed += heal_hooks()
    return fixed


def read_json(path):
    """A JSON settings file, or {} if it does not exist yet. Raises ValueError if it is not valid JSON."""
    return json.loads(path.read_text()) if path.exists() else {}


def heal_hooks(claude=CLAUDE_DIR / "settings.json", codex=CODEX_DIR / "hooks.json"):
    """Add missing hook entries for Claude Code and Codex. Only for a tool whose folder exists."""
    fixed = []
    want = [("PreToolUse", "Bash|Edit|Write|MultiEdit", 15), ("PostToolUse", "Bash", 10),
            ("PostToolUseFailure", "Bash", 10), ("SessionStart", "", 10)]
    try:
        if not claude.parent.is_dir():
            raise OSError("Claude Code not installed")
        s = read_json(claude)
        hooks = s.setdefault("hooks", {})
        changed = False
        for event, matcher, timeout in want:
            entries = hooks.setdefault(event, [])
            if not any("install_guard.py" in h.get("command", "") for e in entries for h in e.get("hooks", [])):
                entry = {"hooks": [{"type": "command", "command": HOOK, "timeout": timeout}]}
                if matcher:
                    entry["matcher"] = matcher
                entries.append(entry)
                fixed.append(f"Claude Code {event} hook restored")
                changed = True
        if changed:
            backup(claude, ".bak-install-guard")
            claude.write_text(json.dumps(s, indent=2) + "\n")
    except (OSError, ValueError):
        pass
    try:
        if not codex.parent.is_dir():
            raise OSError("Codex not installed")
        c = read_json(codex)
        entries = c.setdefault("hooks", {}).setdefault("PreToolUse", [])
        if not any("install_guard.py" in h.get("command", "") for e in entries for h in e.get("hooks", [])):
            entries.append({"matcher": "^Bash$", "hooks": [{"type": "command", "command": CODEX_HOOK, "timeout": 15,
                                                            "statusMessage": "Install guard"}]})
            backup(codex, ".bak-install-guard")
            codex.write_text(json.dumps(c, indent=2) + "\n")
            fixed.append("Codex PreToolUse hook restored")
    except (OSError, ValueError):
        pass
    return fixed


# ---------- the drill ----------

def drill():
    """Return a list of (name, ok, detail)."""
    import fake_registry
    import fake_pypi
    results = []
    work = pathlib.Path(tempfile.mkdtemp(prefix="ig-drill-"))
    markers = work / "markers"
    markers.mkdir()
    import socket

    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    npm_port, py_port = free_port(), free_port()
    fake_registry.serve(str(markers), npm_port)
    fake_pypi.serve(str(markers), py_port)

    # 1. npm, with the real npm and the real ~/.npmrc. Then again with each Homebrew Node keg's npm first in PATH.
    for i, npm in enumerate(["npm"] + install_guard.keg_npms()):
        d = work / f"npm{i}"
        d.mkdir()
        (d / "package.json").write_text('{"name":"drill","version":"1.0.0"}')
        (d / ".npmrc").write_text(f"registry=http://127.0.0.1:{npm_port}/\ncache={work}/npm-cache{i}\n")
        env = None if npm == "npm" else {**os.environ, "PATH": f"{os.path.dirname(npm)}:{os.environ.get('PATH', '')}"}
        r = run([npm, "install", "axios", "--no-audit", "--no-fund"], cwd=d, env=env)
        try:
            lock = json.loads((d / "package-lock.json").read_text())["packages"]
            got = lock.get("node_modules/axios", {}).get("version")
            extra = "node_modules/plain-crypto-js" in lock
        except (OSError, ValueError, KeyError):
            got, extra = None, None
        ok = r.returncode == 0 and got == "1.14.0" and not extra and not any(markers.iterdir())
        name = "npm blocks the Axios replay" + ("" if npm == "npm" else f" ({npm.split('/')[-3]})")
        results.append((name, ok, f"got axios {got}" + ("" if ok else f"; exit {r.returncode}; {r.stderr.strip()[-160:]}")))

    # 2. pip and uv, with the real config files
    venv = work / "venv"
    run([PY, "-m", "venv", str(venv)])
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_"))}
    idx = f"http://127.0.0.1:{py_port}/simple"
    pip = venv / "bin" / "pip"
    pip_v = run([str(pip), "--version"]).stdout.split()[1:2] if pip.exists() else []
    if pip.exists() and pip_v and tuple(int(x) for x in pip_v[0].split(".")[:2] if x.isdigit()) < (26, 1):
        results.append(("pip blocks the replay", False, f"pip {pip_v[0]} from {PY} ignores the 7-day wait; "
                        "set INSTALL_GUARD_PYTHON to a Python whose pip is 26.1 or later"))
    elif pip.exists():
        r = run([str(pip), "install", "-q", "--disable-pip-version-check", "--index-url", idx, "--trusted-host", "127.0.0.1",
                 "requestz"], env=env)
        got = run([str(venv / "bin" / "python"), "-c", "import importlib.metadata as m; print(m.version('requestz'))"]).stdout.strip()
        ok = r.returncode == 0 and got == "2.31.0" and not any(markers.iterdir())
        results.append(("pip blocks the replay", ok, f"got requestz {got or 'none'}" + ("" if ok else f"; {r.stderr.strip()[-160:]}")))
        run([str(pip), "uninstall", "-y", "-q", "requestz"])
    else:
        results.append(("pip blocks the replay", False, "could not create a test venv"))
    if shutil.which("uv"):
        r = run(["uv", "pip", "install", "-q", "--python", str(venv / "bin" / "python"), "--index-url", idx, "requestz"],
                env={**env, "UV_CACHE_DIR": str(work / "uv-cache")})
        got = run([str(venv / "bin" / "python"), "-c", "import importlib.metadata as m; print(m.version('requestz'))"]).stdout.strip()
        ok = r.returncode == 0 and got == "2.31.0" and not any(markers.iterdir())
        results.append(("uv blocks the replay", ok, f"got requestz {got or 'none'}" + ("" if ok else f"; {r.stderr.strip()[-160:]}")))

    # 3. the hook refuses an agent that switches protections off
    for cmd in ("npm install axios --ignore-scripts=false", "pip install requests --no-binary :all:"):
        r = run([sys.executable, str(ROOT / "install_guard.py")], input=json.dumps(
            {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(work)}))
        results.append((f"hook stops: {cmd}", '"deny"' in r.stdout, "denied" if '"deny"' in r.stdout else "NOT denied"))

    # 4. hooks present, for each agent tool that is installed
    if not CLAUDE_DIR.is_dir() and not CODEX_DIR.is_dir():
        results.append(("an agent tool is installed", False, "found neither ~/.claude nor ~/.codex"))
    if CLAUDE_DIR.is_dir():
        try:
            s = read_json(CLAUDE_DIR / "settings.json").get("hooks", {})
            have = [e for e in ("PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart")
                    if any("install_guard.py" in h.get("command", "") for x in s.get(e, []) for h in x.get("hooks", []))]
            results.append(("Claude Code hooks present", len(have) == 4, ", ".join(have) or "missing"))
        except (OSError, ValueError) as e:
            results.append(("Claude Code hooks present", False, str(e)))
    if CODEX_DIR.is_dir():
        try:
            c = read_json(CODEX_DIR / "hooks.json").get("hooks", {})
            ok = any("install_guard.py" in h.get("command", "") for x in c.get("PreToolUse", []) for h in x.get("hooks", []))
            results.append(("Codex hook present", ok, "PreToolUse" if ok else "missing"))
        except (OSError, ValueError) as e:
            results.append(("Codex hook present", False, str(e)))
    shutil.rmtree(work, ignore_errors=True)
    return results


def main():
    t0 = time.monotonic()
    fixed = heal() if "--fix" in sys.argv else []
    results = drill()
    ok = all(r[1] for r in results)
    status = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "ok": ok,
              "fixed": fixed, "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in results],
              "seconds": round(time.monotonic() - t0, 1)}
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    STATUS.write_text(json.dumps(status, indent=1))
    install_guard.log({"ts": status["ts"], "hook": "check", "decision": "ok" if ok else "FAIL", "fixed": fixed,
                       "failed": [n for n, o, _ in results if not o], "ms": round(status["seconds"] * 1000)})
    if "--quiet" not in sys.argv:
        for f in fixed:
            print(f"fixed  {f}")
        for n, o, d in results:
            print(f"{'ok  ' if o else 'FAIL'}   {n}  ({d})")
        print(f"\n{'ALL GOOD' if ok else 'BROKEN'} in {status['seconds']}s")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
