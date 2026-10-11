"""Test 1 for Python: replay an Axios-style attack on pip and uv, end to end, with the guard.

The fake index (fake_pypi.py) serves requestz 2.31.1 -> cryptohelperz (source-only, runs code
at build time), a scriptless import payload (colorlogz 3.1.1) and an old source-only package.
Each scenario plays the agent: pre-hook, the real command (or the redirect), and on failure
the failure hook. Payloads only write marker files.

Usage: python3 tests/replay_python.py [results.json]
Set INSTALL_GUARD_PYTHON to choose the Python for the test venvs (default: python3 on PATH).
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
GUARD = HERE.parent / "install_guard.py"
sys.path.insert(0, str(HERE))
import fake_pypi  # noqa: E402

PORT = 4890
# A Python whose bundled pip is 26.1 or later (pip ignores uploaded-prior-to before 26.1).
PY = os.environ.get("INSTALL_GUARD_PYTHON") or shutil.which("python3") or sys.executable


def main():
    out_json = sys.argv[1] if len(sys.argv) > 1 else None
    work = pathlib.Path(tempfile.mkdtemp(prefix="replaypy-"))
    markers = work / "markers"
    markers.mkdir()
    (work / "home").mkdir()
    fake_pypi.serve(str(markers), PORT)
    idx = f"http://127.0.0.1:{PORT}/simple"
    pip_conf = work / "pip.conf"
    pip_conf.write_text("[global]\nonly-binary = :all:\n[install]\nuploaded-prior-to = P7D\n")
    uv_toml = work / "uv.toml"
    uv_toml.write_text('exclude-newer = "7 days"\n[pip]\nonly-binary = [":all:"]\n')
    empty = work / "empty"
    empty.write_text("")
    results = []

    def hook(event, command, cwd, extra=None):
        ev = {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(cwd), **(extra or {})}
        r = subprocess.run([sys.executable, str(GUARD)], input=json.dumps(ev), capture_output=True, text=True, timeout=60,
                           env={**os.environ, "INSTALL_GUARD_STATE": str(work / "state")})
        return json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else None

    def agent(name, command, protected=True, pyproject=None, follow=True, imp=None):
        for f in markers.iterdir():
            f.unlink()
        d = work / name
        d.mkdir()
        if pyproject:
            (d / "pyproject.toml").write_text(pyproject)
        venv = d / ".venv"
        # A real venv with its own pip, so `pip` can never fall through to another environment.
        subprocess.run([PY, "-m", "venv", str(venv)], check=True, capture_output=True)
        py = str(venv / "bin" / "python")
        env = {**{k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_"))},
               "PIP_CONFIG_FILE": str(pip_conf if protected else empty), "UV_CONFIG_FILE": str(uv_toml if protected else empty),
               "UV_CACHE_DIR": str(work / "uvcache"), "PIP_CACHE_DIR": str(work / "pipcache"), "VIRTUAL_ENV": str(venv),
               # A throwaway HOME, so pip and uv leave nothing (caches, data, tools) in the real one.
               "HOME": str(work / "home"), "XDG_CACHE_HOME": str(work / "home" / ".cache"),
               "XDG_DATA_HOME": str(work / "home" / ".local" / "share"),
               "PATH": f"{venv / 'bin'}:{os.environ['PATH']}"}
        assert shutil.which("pip", path=env["PATH"]) == str(venv / "bin" / "pip"), "pip would not resolve to the test venv"
        full = command.replace("pip install", f"pip install --index-url {idx} --trusted-host 127.0.0.1", 1) \
            if command.startswith("pip ") else command.replace("uv pip install", f"uv pip install --index-url {idx}", 1)
        pre = hook("PreToolUse", full, d)
        ran, hint = full, None
        if pre and pre.get("permissionDecision") == "deny":
            reason = pre["permissionDecisionReason"]
            if not (follow and "Use `" in reason):
                return {"name": name, "command": command, "pre": "deny", "reason": reason, "installed": [], "markers": []}
            ran = full.split(" ", 2)[0] + " " + full.split(" ", 2)[1] + f" --index-url {idx} --trusted-host 127.0.0.1 " + reason.split("`")[1]
            if "uv pip" in full:
                ran = f"uv pip install --index-url {idx} " + reason.split("`")[1]
            assert not hook("PreToolUse", ran, d), "redirect was denied"
        r = subprocess.run(ran, shell=True, cwd=d, env=env, capture_output=True, text=True, timeout=300)
        if r.returncode:
            post = hook("PostToolUseFailure", ran, d, {"error": r.stdout + r.stderr, "tool_exit_code": r.returncode})
            hint = post and post.get("additionalContext")
            if hint and follow and "`" in hint:
                fix = hint.split("`")[1]
                fix = fix.replace("pip install", f"pip install --index-url {idx} --trusted-host 127.0.0.1", 1) if fix.startswith("pip ") \
                    else fix.replace("uv pip install", f"uv pip install --index-url {idx}", 1)
                if not hook("PreToolUse", fix, d):
                    r = subprocess.run(fix, shell=True, cwd=d, env=env, capture_output=True, text=True, timeout=300)
                    ran = fix
        if imp:
            subprocess.run([py, "-c", f"import {imp}"], capture_output=True)
        lst = json.loads(subprocess.run(["uv", "pip", "list", "--python", py, "--format", "json"], capture_output=True, text=True).stdout or "[]")
        return {"name": name, "command": command, "pre": "deny" if pre else "allow", "reason": pre and pre.get("permissionDecisionReason"),
                "ran": ran.replace(f" --index-url {idx} --trusted-host 127.0.0.1", "").replace(f" --index-url {idx}", ""),
                "exit": r.returncode, "hint": hint, "installed": sorted(f"{x['name']}=={x['version']}" for x in lst),
                "markers": sorted(f.name for f in markers.iterdir())}

    def check(row, ok, expect):
        row["pass"], row["expect"] = bool(ok), expect
        results.append(row)

    r = agent("control", "pip install requestz", protected=False)
    check(r, "build-payload-ran" in r["markers"], "control, no protections: the payload runs during install")
    r = agent("pip-direct", "pip install requestz")
    check(r, "requestz==2.31.0" in r["installed"] and not r["markers"], "pip: gets 2.31.0, nothing runs")
    r = agent("pip-transitive", "pip install sitetoolz")
    check(r, "requestz==2.31.0" in r["installed"] and not r["markers"], "pip: requestz arrives underneath: still 2.31.0")
    r = agent("pip-pinned", "pip install requestz==2.31.1")
    check(r, r["pre"] == "deny" and r["exit"] == 0 and "requestz==2.31.0" in r["installed"] and not r["markers"],
          "pip: agent pins the bad version: redirected to 2.31.0, keeps working")
    r = agent("pip-scriptless", "pip install colorlogz", imp="colorlogz")
    check(r, "colorlogz==3.1.0" in r["installed"] and not r["markers"], "pip: scriptless payload on import: gets 3.1.0, never runs")
    r = agent("pip-no-wheel", "pip install oldsdistz")
    check(r, r["hint"] and r["exit"] == 0 and "oldsdistz==0.9.0" in r["installed"],
          "pip: old package with no wheel: hint, then the agent builds just that one")
    r = agent("pip-switch-off", "pip install requestz --no-binary :all:", follow=False)
    check(r, r["pre"] == "deny" and not r["markers"], "pip: agent forces source builds: stopped")
    r = agent("pip-isolated", "pip install --isolated requestz", follow=False)
    check(r, r["pre"] == "deny", "pip: agent skips the config with --isolated: stopped")
    r = agent("uv-direct", "uv pip install requestz")
    check(r, "requestz==2.31.0" in r["installed"] and not r["markers"], "uv: gets 2.31.0, nothing runs")
    r = agent("uv-pinned", "uv pip install requestz==2.31.1")
    check(r, r["pre"] == "deny" and "requestz==2.31.0" in r["installed"], "uv: pinned bad version: redirected to 2.31.0")
    r = agent("uv-switch-off", "uv pip install requestz --exclude-newer false", follow=False)
    check(r, r["pre"] == "deny", "uv: agent switches the 7-day wait off: stopped")
    r = agent("uv-bad-project", "uv pip install requestz", follow=False,
              pyproject='[project]\nname = "x"\n[tool.uv]\nexclude-newer = "1 hour"\n')
    check(r, r["pre"] == "deny" and "--exclude-newer" in (r["reason"] or ""), "uv: a repo's pyproject weakens the wait: stopped, with the fix")
    r = agent("uv-no-wheel", "uv pip install oldsdistz")
    check(r, r["hint"] and "oldsdistz==0.9.0" in r["installed"], "uv: old package with no wheel: hint, then just that one builds")

    width = max(len(r["name"]) for r in results)
    for r in results:
        print(f"{'PASS' if r['pass'] else 'FAIL'}  {r['name']:<{width}}  {r['expect']}")
        if not r["pass"]:
            print("      ", json.dumps({k: r.get(k) for k in ("pre", "reason", "ran", "exit", "hint", "installed", "markers")})[:700])
    passed = sum(r["pass"] for r in results)
    print(f"\n{passed}/{len(results)} passed")
    if out_json:
        pathlib.Path(out_json).write_text(json.dumps(results, indent=1))
    shutil.rmtree(work, ignore_errors=True)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
