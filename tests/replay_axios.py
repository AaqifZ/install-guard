"""Test 1: replay 31 March 2026 end to end, with a harmless copy of the attack.

A fake registry serves axios 1.14.1 -> plain-crypto-js (postinstall payload),
a transitive path (site-tool -> axios ^1.14.0) and a scriptless hijack (colorlog).
The payloads only write marker files. Each scenario plays the agent:
pre-hook, the real npm command, post-hook. Then it checks what landed on disk.

Usage: python3 tests/replay_axios.py [npm-bin-dir] [results.json]
(default npm-bin-dir: the folder of the npm on PATH; it must hold npm 11.10 or later)
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
import fake_registry  # noqa: E402

PORT = 4874


def main():
    npm_bin = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(shutil.which("npm")).parent
    out_json = sys.argv[2] if len(sys.argv) > 2 else None
    work = pathlib.Path(tempfile.mkdtemp(prefix="replay-"))
    markers = work / "markers"
    markers.mkdir()
    fake_registry.serve(str(markers), PORT)
    home = work / "home"
    home.mkdir()
    (home / ".npmrc").write_text("ignore-scripts=true\nmin-release-age=7\n")
    results = []

    def env_for(state, npm_dir):
        return {**os.environ, "HOME": str(home), "INSTALL_GUARD_STATE": str(state),
                "INSTALL_GUARD_NOTIFY_LOG": str(state / "notifications.jsonl"), "INSTALL_GUARD_FOREGROUND": "1",
                "PATH": f"{npm_dir}:{os.environ['PATH']}"}

    def hook(event, command, cwd, env):
        r = subprocess.run([sys.executable, str(GUARD)], input=json.dumps(
            {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(cwd)}),
            capture_output=True, text=True, env=env, timeout=60)
        return json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else None

    def project(name, npmrc_extra=""):
        d = work / name
        d.mkdir()
        (d / "package.json").write_text('{"name":"p","version":"1.0.0"}')
        (d / ".npmrc").write_text(f"registry=http://127.0.0.1:{PORT}/\ncache={work}/cache-{name}\n{npmrc_extra}")
        return d

    def installed(d):
        try:
            pk = json.loads((d / "package-lock.json").read_text())["packages"]
            return sorted(k.split("node_modules/")[-1] + "@" + v["version"] for k, v in pk.items() if k)
        except (OSError, ValueError, KeyError):
            return []

    def agent(name, command, npm_dir=npm_bin, npmrc_extra="", follow=True, run_import=None):
        """Play one agent step: pre-hook, run (or follow the redirect), post-hook."""
        for f in markers.iterdir():
            f.unlink()
        d = project(name, npmrc_extra)
        state = work / f"state-{name}"
        state.mkdir()
        env = env_for(state, npm_dir)
        pre = hook("PreToolUse", command, d, env)
        ran = command
        if pre and pre.get("permissionDecision") == "deny":
            reason = pre["permissionDecisionReason"]
            redirect = reason.split("`")[1] if "Use `" in reason else None
            if not (follow and redirect):
                return {"name": name, "command": command, "pre": "deny", "reason": reason, "ran": None,
                        "installed": [], "markers": [], "notifications": 0, "post": None}
            ran = f"npm install {redirect}"
            pre2 = hook("PreToolUse", ran, d, env)
            assert not pre2, f"redirected command was denied: {pre2}"
        r = subprocess.run(ran, shell=True, cwd=d, env=env, capture_output=True, text=True, timeout=120)
        post = hook("PostToolUse", ran, d, env)
        if run_import:
            subprocess.run(["node", "-e", f"require('{run_import}')"], cwd=d, env=env, capture_output=True)
        notes = state / "notifications.jsonl"
        lines = notes.read_text().splitlines() if notes.exists() else []
        return {"name": name, "command": command, "pre": "deny" if pre else "allow",
                "reason": pre["permissionDecisionReason"] if pre else None, "ran": ran, "exit": r.returncode,
                "installed": installed(d), "markers": sorted(f.name for f in markers.iterdir()),
                "notifications": len(lines), "post": json.loads(lines[-1])["text"] if lines else None}

    def check(row, ok, expect):
        row["pass"], row["expect"] = bool(ok), expect
        results.append(row)

    old_npm = pathlib.Path(shutil.which("npm")).parent

    # Control: no guard, both protections switched off. Proves the payload is live.
    for f in markers.iterdir():
        f.unlink()
    d = work / "control-raw"
    d.mkdir()
    (d / "package.json").write_text('{"name":"p","version":"1.0.0"}')
    (d / ".npmrc").write_text(f"registry=http://127.0.0.1:{PORT}/\ncache={work}/cache-raw\n")
    subprocess.run("npm install axios --ignore-scripts=false --min-release-age=0", shell=True, cwd=d, capture_output=True,
                   env={**os.environ, "HOME": str(home), "PATH": f"{old_npm}:{os.environ['PATH']}"}, timeout=120)
    raw = {"name": "control: no guard, protections off", "command": "npm install axios --ignore-scripts=false --min-release-age=0",
           "installed": installed(d), "markers": sorted(f.name for f in markers.iterdir())}
    check(raw, "install-script-ran" in raw["markers"], "the payload is live: marker file written")

    r = agent("direct", "npm install axios")
    check(r, r["pre"] == "allow" and "axios@1.14.0" in r["installed"] and not r["markers"]
          and r["notifications"] == 1 and r["post"] and "plain-crypto-js" in r["post"],
          "agent gets axios 1.14.0, nothing runs, exactly one notification")

    r = agent("transitive", "npm install site-tool")
    check(r, "axios@1.14.0" in r["installed"] and not any("plain-crypto" in x for x in r["installed"])
          and not r["markers"] and r["notifications"] == 1,
          "axios arrives underneath site-tool: still 1.14.0, one notification")

    r = agent("pinned", "npm install axios@1.14.1")
    check(r, r["pre"] == "deny" and r["ran"] == "npm install axios@1.14.0" and r["exit"] == 0
          and "axios@1.14.0" in r["installed"] and not r["markers"],
          "agent pins the bad version: redirected to axios@1.14.0 and keeps working")

    r = agent("pinned-old-line", "npm install axios@0.30.4")
    check(r, r["pre"] == "deny" and r["ran"] == "npm install axios@0.30.3" and "axios@0.30.3" in r["installed"],
          "second bad version (0.30.4): redirected to 0.30.3, not to another bad one")

    r = agent("scripts-on", "npm install axios --ignore-scripts=false", follow=False)
    check(r, r["pre"] == "deny" and not r["markers"], "agent tries to switch scripts on: stopped")

    r = agent("cooldown-off", "npm install axios --min-release-age=0", follow=False)
    check(r, r["pre"] == "deny", "agent tries to switch the 7-day wait off: stopped")

    r = agent("bad-npmrc", "npm install axios", npmrc_extra="ignore-scripts=false\nmin-release-age=0\n", follow=False)
    check(r, r["pre"] == "deny" and "--ignore-scripts --min-release-age=7" in (r["reason"] or ""),
          "a cloned repo's .npmrc switches protections off: stopped, with the fix")

    r = agent("scriptless", "npm install colorlog", run_import="colorlog")
    check(r, "colorlog@3.1.0" in r["installed"] and not r["markers"],
          "scriptless hijack (payload runs on import): agent gets 3.1.0, payload never runs")

    r = agent("legit-fresh", "npm install fastbuild")
    check(r, r["pre"] == "allow" and r["exit"] == 0 and r["notifications"] == 0,
          "normal fresh release with a long-standing script: quiet, no notification")

    r = agent("other-major-line", "npm install needs-tarlike")
    check(r, "tarlike@2.2.0" in r["installed"] and r["notifications"] == 0,
          "a young release on a line npm would never pick: no false alarm")

    r = agent("established-dep", "npm install sitegen")
    check(r, "sitegen@7.3.5" in r["installed"] and r["notifications"] == 0,
          "a fresh release adds a long-established scripted dependency: no false alarm")

    # The 7-day wait failed (an old npm got in): the lockfile holds the young bad release. The note must say it RAN.
    d = project("ran")
    state = work / "state-ran"
    state.mkdir()
    (d / "package-lock.json").write_text(json.dumps({"packages": {
        "": {"name": "p"}, "node_modules/axios": {"version": "1.14.1"},
        "node_modules/plain-crypto-js": {"version": "4.2.1"}}}))
    hook("PostToolUse", "npm install axios", d, env_for(state, npm_bin))
    notes = state / "notifications.jsonl"
    lines = notes.read_text().splitlines() if notes.exists() else []
    note = json.loads(lines[-1]) if lines else {}
    check({"name": "ran", "command": "npm install axios", "notifications": len(lines), "post": note.get("text")},
          len(lines) == 1 and "RAN" in note.get("text", "") and "ran" in note.get("title", "").lower(),
          "a too-new release got installed anyway: one notification that says it RAN")

    for f in markers.iterdir():
        f.unlink()
    d = project("npx")
    env = env_for(work / "state-npx", npm_bin)
    (work / "state-npx").mkdir()
    pre = hook("PreToolUse", "npx --yes colorlog", d, env)
    subprocess.run("npx --yes colorlog", shell=True, cwd=d, env=env, capture_output=True, timeout=120)
    check({"name": "npx", "command": "npx --yes colorlog", "pre": "deny" if pre else "allow",
           "markers": sorted(f.name for f in markers.iterdir())},
          not pre and not any(markers.iterdir()), "npx runs the tool: older safe version, payload never runs")

    width = max(len(r["name"]) for r in results)
    for r in results:
        print(f"{'PASS' if r['pass'] else 'FAIL'}  {r['name']:<{width}}  {r['expect']}")
        if not r["pass"]:
            print("      ", json.dumps({k: r.get(k) for k in ("pre", "reason", "ran", "exit", "installed", "markers", "notifications", "post")})[:600])
    passed = sum(r["pass"] for r in results)
    print(f"\n{passed}/{len(results)} passed")
    if out_json:
        pathlib.Path(out_json).write_text(json.dumps(results, indent=1))
    shutil.rmtree(work, ignore_errors=True)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
