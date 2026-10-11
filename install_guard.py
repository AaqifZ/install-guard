#!/usr/bin/env python3
"""Install Guard: keep npm's install protections on, and keep the agent moving.

npm 11 does the protecting, from ~/.npmrc:
  ignore-scripts=true   install scripts never run
  min-release-age=7     releases younger than 7 days are never installed
This hook does three small jobs around it:
  1. Stop the agent from switching those protections off.
  2. When the cooldown would block an exact new version, hand the agent an older one.
  3. After an install, notice when the cooldown skipped a hijack-shaped release, and say so once.
     Hijack-shaped = a young release that adds a dependency which runs an install script.
     Rules only. A small LLM classifier was tested here and removed: it never reached a confident answer.
Uncertain or broken cases allow. Stdlib only.
"""
import datetime
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))  # pyguard.py sits beside this file, even under python -I
LOG = ROOT / "logs" / "install-guard.jsonl"
STATE = pathlib.Path(os.environ.get("INSTALL_GUARD_STATE", pathlib.Path.home() / ".cache" / "install-guard"))
USER_NPMRC = pathlib.Path.home() / ".npmrc"
DEFAULT_REGISTRY = "https://registry.npmjs.org/"
MIN_NPM = (11, 10, 0)
NEW_PACKAGE_DAYS = 30   # a dependency created this recently counts as "brand new"
POST_DEADLINE = 8.0     # seconds the after-install check may take

# Packages that may run their own install script through `npm rebuild <name> --ignore-scripts=false`.
REBUILD_OK = {"sharp", "esbuild", "better-sqlite3", "sqlite3", "bcrypt", "canvas", "puppeteer",
              "@swc/core", "@parcel/watcher", "node-pty", "fsevents", "re2", "keytar"}

# Packages that do not work at all until their install script runs (native build or browser download).
NEEDS_BUILD = {"better-sqlite3", "sqlite3", "puppeteer", "canvas", "node-pty", "re2", "keytar"}

INSTALL = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
           "add", "update", "up", "upgrade", "udpate"}
EXEC = {"exec", "x"}
CI = {"ci", "clean-install", "ic", "install-clean", "isntall-clean"}
REBUILD = {"rebuild", "rb"}
CONFIG = {"config", "c", "set", "get", "delete"}
VALUE_FLAGS = {"--prefix", "-C", "--registry", "--cache", "--userconfig", "--globalconfig", "--workspace",
               "-w", "--before", "--min-release-age", "--tag", "--omit", "--include", "--loglevel",
               "--package", "-p", "--call", "-c"}
WRAPPERS = {"command", "env", "nice", "nohup", "time", "sudo", "exec"}
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "|&"}


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def cooldown_days():
    """The cooldown the user chose in ~/.npmrc. Defaults to 7 days."""
    try:
        for line in USER_NPMRC.read_text().splitlines():
            m = re.match(r"\s*min-release-age\s*=\s*\"?(\d+)", line)
            if m:
                return int(m.group(1))
    except OSError:
        pass
    return 7


# ---------- reading commands ----------

def segments(command):
    """Split a shell command into simple commands, each a list of words."""
    text = command.replace("\\\n", " ").replace("\n", " ; ")
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=";&|()")
        lex.whitespace_split = True
        words = list(lex)
    except ValueError:
        words = text.split()
    out, cur = [], []
    for w in words:
        if w in SEPARATORS:
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(w)
    if cur:
        out.append(cur)
    return out


def unwrap(argv):
    """Return (env assignments, argv) without leading assignments and wrappers."""
    env = {}
    while argv:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", argv[0])
        if m:
            env[m.group(1)] = m.group(2)
            argv = argv[1:]
        elif os.path.basename(argv[0]) in WRAPPERS:
            argv = argv[1:]
            while argv and argv[0].startswith("-"):
                argv = argv[1:]
        else:
            break
    return env, argv


def parse_npm(argv):
    """Describe one npm/npx call: kind, subcommand words, flags, package specs."""
    prog = os.path.basename(argv[0])
    rest = argv[1:]
    words, flags, i = [], [], 0
    while i < len(rest):
        t = rest[i]
        if t.startswith("-"):
            if t in VALUE_FLAGS and "=" not in t and i + 1 < len(rest):
                flags.append(f"{t}={rest[i + 1]}")
                i += 1
            elif t == "--ignore-scripts" and i + 1 < len(rest) and rest[i + 1] in ("true", "false", "0", "1"):
                flags.append(f"{t}={rest[i + 1]}")
                i += 1
            else:
                flags.append(t)
        else:
            words.append(t)
        i += 1
    if prog == "npx":
        kind, specs = "exec", words[:1]
    else:
        sub = words[0] if words else ""
        kind = ("install" if sub in INSTALL else "exec" if sub in EXEC else "ci" if sub in CI
                else "rebuild" if sub in REBUILD else "config" if sub in CONFIG else "other")
        specs = words[1:]
        if kind == "exec":
            specs = [f.split("=", 1)[1] for f in flags if f.startswith(("--package=", "-p="))] or words[1:2]
    is_global = any(f in ("-g", "--global", "--location=global") for f in flags)
    return {"prog": prog, "kind": kind, "words": words, "flags": flags, "specs": specs, "global": is_global}


# ---------- job 1: protections stay on ----------

WEAK_LINE = re.compile(r"^\s*(ignore-scripts\s*=\s*(false|0)\b|min-release-age\s*=\s*\"?(\d+)|before\s*=)", re.M | re.I)


def weak_npmrc_text(text, days):
    """Lines in .npmrc text that switch a protection off."""
    found = []
    for m in WEAK_LINE.finditer(text or ""):
        if m.group(3) is not None and int(m.group(3)) >= days:
            continue
        found.append(m.group(0).strip())
    return found


def weak_npmrc_write(command, days):
    """A shell command that writes a weakening line into some .npmrc."""
    writes = re.search(r">>?\s*['\"]?[^\s;&|'\"]*\.npmrc|\btee\b[^;&|]*\.npmrc|\bsed\b[^;&|]*\s-i[^;&|]*\.npmrc|"
                       r"\b(cp|mv|ln)\b[^;&|]*\.npmrc", command)
    if not writes:
        return []
    found = []
    for m in re.finditer(r"(ignore-scripts\s*=\s*(false|0)\b|min-release-age\s*=\s*\"?(\d+)|\bbefore\s*=)", command, re.I):
        if m.group(3) is not None and int(m.group(3)) >= days:
            continue
        found.append(m.group(0))
    return found


def weak_flags(npm, env, days):
    """Flags or environment variables in one npm call that switch a protection off."""
    found = []
    for f in npm["flags"]:
        low = f.lower()
        if low in ("--ignore-scripts=false", "--ignore-scripts=0", "--no-ignore-scripts"):
            found.append(f)
        elif low.startswith("--min-release-age="):
            value = low.split("=", 1)[1]
            if not value.isdigit() or int(value) < days:
                found.append(f)
        elif low.startswith("--before="):
            found.append(f)
        elif low.startswith(("--userconfig", "--globalconfig")):
            found.append(f)  # a different config file can drop ignore-scripts and min-release-age
    for key, value in env.items():
        k = key.lower()
        if k == "npm_config_ignore_scripts" and value.lower() in ("false", "0", ""):
            found.append(f"{key}={value}")
        elif k == "npm_config_min_release_age" and (not value.isdigit() or int(value) < days):
            found.append(f"{key}={value}")
        elif k in ("npm_config_before", "npm_config_userconfig", "npm_config_globalconfig"):
            found.append(f"{key}={value}")
    if npm["kind"] == "config":
        w = [x.lower() for x in npm["words"]]
        if w and w[0] in ("config", "c"):
            w = w[1:]
        action, args = (w[0] if w else ""), " ".join(w[1:]).replace("=", " ").split()
        if action in ("set", "delete", "rm", "edit") and any(re.match(r"ignore-scripts|min-release-age|before", a) for a in args):
            strengthens = action == "set" and len(args) == 2 and (
                (args[0] == "ignore-scripts" and args[1] == "true") or
                (args[0] == "min-release-age" and args[1].isdigit() and int(args[1]) >= days))
            if not strengthens:
                found.append("npm " + " ".join(npm["words"]))
    return found


def project_npmrc_weakness(cwd, days):
    """Project .npmrc files (cwd and parents, not ~/.npmrc) that switch a protection off."""
    found = []
    path = pathlib.Path(cwd)
    for folder in [path, *path.parents]:
        rc = folder / ".npmrc"
        if rc == USER_NPMRC or not rc.is_file():
            continue
        try:
            for line in weak_npmrc_text(rc.read_text(), days):
                found.append(f"{rc}: {line}")
        except OSError:
            pass
    return found


# ---------- registry ----------

def registry_for(cwd):
    """The registry npm will use: env, then project .npmrc, then ~/.npmrc."""
    if os.environ.get("npm_config_registry"):
        return os.environ["npm_config_registry"]
    path = pathlib.Path(cwd)
    for rc in [*(f / ".npmrc" for f in [path, *path.parents]), USER_NPMRC]:
        try:
            m = re.search(r"^\s*registry\s*=\s*(\S+)", rc.read_text(), re.M)
            if m:
                return m.group(1)
        except OSError:
            continue
    return DEFAULT_REGISTRY


def packument(name, registry, timeout=4.0):
    """Full registry record for a package, or None."""
    import urllib.parse
    import urllib.request
    url = registry.rstrip("/") + "/" + urllib.parse.quote(name, safe="@")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


def parse_time(text):
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def vtuple(v):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def split_spec(spec):
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3'). Non-registry specs -> (None, None)."""
    if re.match(r"^(\.|/|~|file:|git[+:]|https?:|github:|npm:)", spec) or spec.count("/") > (1 if spec.startswith("@") else 0):
        return None, None
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1:]
    return spec, ""


def has_script(meta):
    meta = meta or {}
    return bool(meta.get("hasInstallScript")) or any(k in (meta.get("scripts") or {}) for k in ("preinstall", "install", "postinstall"))


def aged_versions(doc, cutoff):
    """Stable versions published before the cutoff, newest first."""
    times = doc.get("time") or {}
    out = []
    for v in (doc.get("versions") or {}):
        t, vt = parse_time(times.get(v)), vtuple(v)
        if vt and t and t <= cutoff:
            out.append((vt, v))
    return [v for _, v in sorted(out, reverse=True)]


# ---------- job 2: unstick the agent ----------

def check_specs(npm, cwd, days):
    """Exact version pins younger than the cooldown, each with an older version to use instead."""
    cutoff = now() - datetime.timedelta(days=days)
    registry = registry_for(cwd)
    wanted = []
    for spec in npm["specs"]:
        name, version = split_spec(spec)
        if name and vtuple(version):  # only exact pins: npm already picks an old-enough version for the rest
            wanted.append((spec, name, version))
    if not wanted:
        return [], 0
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        docs = list(pool.map(lambda w: packument(w[1], registry), wanted))
    problems, failed = [], 0
    for (spec, name, version), doc in zip(wanted, docs):
        if not doc:
            failed += 1
            continue
        old = aged_versions(doc, cutoff)
        t = parse_time((doc.get("time") or {}).get(version))
        if t and t > cutoff:
            same_major = [v for v in old if vtuple(v)[0] == vtuple(version)[0]]
            pick = (same_major or old or [None])[0]
            problems.append({"spec": spec, "name": name, "age_hours": round((now() - t).total_seconds() / 3600),
                             "use": f"{name}@{pick}" if pick else None})
    return problems, failed


def old_npm_spec(npm):
    """An `npm@<version>` spec older than MIN_NPM (npm before 11.10 ignores min-release-age), or None."""
    if npm["kind"] not in ("install", "exec"):
        return None
    for spec in npm["specs"]:
        name, version = split_spec(spec)
        if name != "npm" or not version:
            continue
        m = re.match(r"^(latest-)?([~=v]*)(\d+)(?:\.(\d+))?", version)
        if not m:
            continue
        major, minor = int(m.group(3)), m.group(4)
        exact_minor = minor is not None and not m.group(1) and (m.group(2).startswith("~") or re.fullmatch(r"[=v]*\d+\.\d+\.\d+", version))
        if major < MIN_NPM[0] or (exact_minor and (major, int(minor)) < MIN_NPM[:2]):
            return spec
    return None


def old_npm_reason(spec):
    v = ".".join(map(str, MIN_NPM[:2]))
    return (f"Install Guard: {spec} is older than npm {v}. Older npm ignores min-release-age, so new releases "
            "would skip the 7-day wait. Use `npm install -g npm@11.20.0` instead.")


# ---------- protected config files ----------

PIP_SHADOW = pathlib.Path.home() / "Library" / "Application Support" / "pip"  # pip on macOS prefers this folder
REMOVERS = {"rm", "unlink", "shred", "srm", "trash", "truncate", "mv"}
COPIERS = {"cp", "ln", "install", "rsync", "ditto"}
CREATORS = {"mkdir", "touch", "tee"} | COPIERS | {"mv"}
TARGET = r"\s*(\"[^\"]*\"|'[^']*'|(?:\\ |[^\s;&|<>()])+)"
REDIRECT = re.compile(r"(?:^|[^>&0-9])[0-9]?>\|?(?![>&])" + TARGET)  # > and >| (overwrite), not >> or 2>&1
APPEND = re.compile(r">>" + TARGET)


def protected_files():
    import pyguard
    return [USER_NPMRC, pyguard.PIP_CONF, pyguard.UV_TOML]


def resolve(word, cwd):
    """A shell word as an absolute path: ~ and $HOME expanded, relative to cwd."""
    home = str(pathlib.Path.home())
    w = word.strip("'\"").replace("\\ ", " ")
    for prefix in ("${HOME}", "$HOME", "~"):
        if w == prefix or w.startswith(prefix + "/"):
            w = home + w[len(prefix):]
            break
    return os.path.normpath(os.path.join(cwd, w))


def hits(path, target):
    """True if path is the target or one of its parent folders."""
    t = str(target)
    return path == t or (path != "/" and t.startswith(path.rstrip("/") + "/"))


def config_damage(command, cwd):
    """Shell commands that delete, truncate or replace a protected config file, or create pip's macOS folder."""
    found, here = [], cwd
    for argv in segments(command):
        _, argv = unwrap(argv)
        if not argv:
            continue
        if argv[0] == "cd" and len(argv) > 1:
            here = resolve(argv[1], here)
            continue
        prog = os.path.basename(argv[0])
        args = [a for a in argv[1:] if not a.startswith("-")]
        sed_inplace = prog == "sed" and any(a.startswith("-i") or a == "--in-place" for a in argv[1:])
        targets = args if prog in REMOVERS or sed_inplace else args[-1:] if prog in COPIERS else []
        for t in targets:
            if any(hits(resolve(t, here), f) for f in protected_files()):
                found.append(f"{prog} {t}")
        if prog in CREATORS and any(hits(str(PIP_SHADOW), resolve(a, here)) for a in args):
            found.append("create " + str(PIP_SHADOW))
    for m in REDIRECT.finditer(command):
        if any(resolve(m.group(1), cwd) == str(f) for f in protected_files()):
            found.append("> " + m.group(1))
    for m in list(REDIRECT.finditer(command)) + list(APPEND.finditer(command)):
        if hits(str(PIP_SHADOW), resolve(m.group(1), cwd)):
            found.append("create " + str(PIP_SHADOW))
    return sorted(set(found))


def damage_reason(found):
    if any(f.startswith("create ") for f in found):
        return (f"Install Guard: on macOS, pip ignores ~/.config/pip/pip.conf once {PIP_SHADOW} exists, so this would "
                "switch off the pip protections (wheels only, 7-day wait). Keep pip settings in ~/.config/pip/pip.conf: "
                "use `pip config --user set <key> <value>`.")
    return ("Install Guard: this would delete, truncate or replace a file that holds the install protections ("
            + ", ".join(found) + "). To change one setting, use `npm config set <key> <value>` or "
            "`pip config --user set <key> <value>`, or append a line with `>>`.")


def edit_damage(path, text, old, full):
    """A Write that drops a protection from a user config file, or an Edit that removes one."""
    import pyguard
    p = os.path.normpath(os.path.expanduser(path or ""))
    if hits(str(PIP_SHADOW), p):
        return damage_reason(["create " + str(PIP_SHADOW)])
    keep = {str(USER_NPMRC): (r"^\s*ignore-scripts\s*=\s*true", r"^\s*min-release-age\s*="),
            str(pyguard.PIP_CONF): (r"only-binary\s*=\s*:all:", r"uploaded-prior-to\s*="),
            str(pyguard.UV_TOML): (r"exclude-newer\s*=", r":all:")}.get(p)
    if not keep:
        return None
    if full:
        missing = [k for k in keep if not re.search(k, text or "", re.M | re.I)]
    else:
        missing = [k for k in keep if re.search(k, old or "", re.M | re.I) and not re.search(k, text or "", re.M | re.I)]
    if not missing:
        return None
    return (f"Install Guard: this edit would remove an install protection from {path}. Keep the "
            "ignore-scripts, min-release-age, only-binary, uploaded-prior-to and exclude-newer lines as they are, "
            "and change only the other lines.")


# ---------- decide before the command ----------

BASH_TRIGGER = re.compile(r"\b(npm|npx|pip3?(\.\d+)?|uvx?|corepack|pnpm|pnpx|yarn|yarnpkg|bunx?)\b|npm_config_|\.npmrc|"
                          r"\bPIP_|\bUV_|XDG_CONFIG_HOME|pip\.conf|pip\.ini|uv\.toml|pyproject\.toml|Application.{1,2}Support", re.I)


def decide_command(command, cwd):
    """(decision, reason, facts) for one Bash command, or None if it never touches packages or their config."""
    if not BASH_TRIGGER.search(command):
        return None
    days = cooldown_days()
    damage = config_damage(command, cwd)
    if damage:
        return "deny", damage_reason(damage), {}
    written = weak_npmrc_write(command, days)
    if written:
        return "deny", off_reason(written), {}
    if re.search(r"pip\.conf|pip\.ini|uv\.toml|pyproject\.toml", command):
        import pyguard
        written = pyguard.weak_write(command, days)
        if written:
            return "deny", pyguard.off_reason(written, days), {}
    return decide_bash(command, cwd)



def decide_bash(command, cwd):
    """Return (decision, reason, facts). decision is allow or deny."""
    days = cooldown_days()
    facts = {"npm_calls": 0}
    here = cwd
    for argv in segments(command):
        env, argv = unwrap(argv)
        if not argv:
            weak = weak_flags({"flags": [], "kind": "other", "words": []}, env, days)
            if weak:
                return "deny", off_reason(weak), facts
            py_weak = py_env_weakness(env, days)
            if py_weak:
                return "deny", py_weak, facts
            continue
        if argv[0] == "cd" and len(argv) > 1:
            target = pathlib.Path(os.path.expanduser(argv[1]))
            here = str(target if target.is_absolute() else pathlib.Path(here) / target)
            continue
        if argv[0] == "export":
            exported = dict(a.split("=", 1) for a in argv[1:] if "=" in a)
            weak = weak_flags({"flags": [], "kind": "other", "words": []}, exported, days)
            if weak:
                return "deny", off_reason(weak), facts
            py_weak = py_env_weakness(exported, days)
            if py_weak:
                return "deny", py_weak, facts
            continue
        if os.path.basename(argv[0]) in ("sh", "bash", "zsh", "dash", "ksh", "eval") and len(argv) > 1:
            flag = next((i for i, a in enumerate(argv[1:-1], 1) if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a)), None)
            inner = argv[flag + 1] if flag else " ".join(argv[1:]) if argv[0] == "eval" else None
            if inner:
                result = decide_bash(inner, here)
                if result[0] == "deny":
                    return result
            continue
        if os.path.basename(argv[0]) in OTHER_PMS:
            return "deny", other_pm_reason(argv), facts
        if os.path.basename(argv[0]) in ("npm", "npx"):
            exec_of = parse_npm(argv)
            if exec_of["kind"] == "exec" and exec_of["specs"] and split_spec(exec_of["specs"][0])[0] in OTHER_PMS:
                return "deny", other_pm_reason(exec_of["words"][1 if exec_of["prog"] == "npm" else 0:]), facts
        if re.fullmatch(r"pip(3(\.\d+)?)?|uvx?|python(3(\.\d+)?)?", os.path.basename(argv[0])):
            import pyguard
            result = pyguard.decide(argv, env, here, days)
            if result:
                facts.update(result[2])
                if result[0] == "deny":
                    return result[0], result[1], facts
            continue
        if os.path.basename(argv[0]) not in ("npm", "npx"):
            continue
        npm = parse_npm(argv)
        facts["npm_calls"] += 1
        weak = weak_flags(npm, env, days)
        if weak and npm["kind"] == "rebuild" and npm["specs"] and all(s in REBUILD_OK for s in npm["specs"]) \
                and all(w.lower() in ("--ignore-scripts=false", "--no-ignore-scripts") for w in weak):
            facts["trusted_rebuild"] = npm["specs"]
            continue
        if weak:
            return "deny", off_reason(weak), facts
        old_npm = old_npm_spec(npm)
        if old_npm:
            return "deny", old_npm_reason(old_npm), facts
        if npm["kind"] not in ("install", "exec", "ci", "rebuild"):
            continue
        weak_rc = project_npmrc_weakness(here, days)
        overridden = any(f in ("--ignore-scripts", "--ignore-scripts=true") for f in npm["flags"]) and any(
            f.startswith("--min-release-age=") and f.split("=", 1)[1].isdigit() and int(f.split("=", 1)[1]) >= days
            for f in npm["flags"])
        if weak_rc and not overridden:
            return "deny", npmrc_reason(weak_rc, days), facts
        if npm["kind"] in ("install", "exec") and npm["specs"]:
            t0 = time.monotonic()
            problems, failed = check_specs(npm, here, days)
            facts.update(registry_ms=round((time.monotonic() - t0) * 1000), registry_failed=failed)
            if problems:
                facts["problems"] = problems
                return "deny", young_reason(problems, days), facts
        if npm["kind"] == "install" and not npm["global"]:
            snapshot(here)
    return "allow", None, facts


def py_env_weakness(env, days):
    """Reason text if environment assignments switch off a pip/uv protection, else None."""
    if not any(k.upper().startswith(("PIP_", "UV_")) or k.upper() == "XDG_CONFIG_HOME" for k in env):
        return None
    import pyguard
    weak = pyguard.weak_call({"tool": "pip", "sub": "", "flags": [], "specs": []}, env, days)
    return pyguard.off_reason(weak, days) if weak else None


def decide_edit(path, text, old=None, full=False):
    days = cooldown_days()
    damage = edit_damage(path, text, old, full)
    if damage:
        return "deny", damage, {}
    name = os.path.basename(path or "")
    if name in ("pip.conf", "pip.ini", "uv.toml", "pyproject.toml"):
        import pyguard
        result = pyguard.decide_edit(path, text, days)
        if result:
            return result
    if path and os.path.basename(path) == ".npmrc":
        weak = weak_npmrc_text(text, days)
        if weak:
            return "deny", off_reason(weak), {}
    return "allow", None, {}


OTHER_PMS = ("corepack", "pnpm", "pnpx", "yarn", "yarnpkg", "bun", "bunx")


def other_pm_reason(argv):
    """pnpm, yarn and bun (often fetched by corepack, which ships with Node) skip the npm protections. Hand over npm."""
    words = [os.path.basename(argv[0])] + list(argv[1:]) if argv else ["npm"]
    tool = words[0]
    if tool == "corepack":
        if len(words) > 1 and words[1] in OTHER_PMS:
            return other_pm_reason(words[1:])
        npm_cmd = "npm install"
    elif tool in ("pnpx", "bunx"):
        npm_cmd = "npx " + " ".join(words[1:])
    else:
        sub, rest = (words[1], words[2:]) if len(words) > 1 else ("install", [])
        if sub in ("install", "i", "add"):
            npm_cmd = " ".join(["npm install"] + rest)
        elif sub in ("dlx", "x", "exec"):
            npm_cmd = "npx " + " ".join(rest)
        elif sub == "run":
            npm_cmd = " ".join(["npm run"] + rest)
        elif sub.startswith("-"):
            npm_cmd = "npm install"
        else:  # `yarn build` and `pnpm test` run a package.json script
            npm_cmd = " ".join(["npm run", sub] + rest)
    return (f"Install Guard: {tool} skips this machine's install protections (no install scripts, 7-day wait). "
            f"Use npm instead: `{npm_cmd.strip()}`.")


def off_reason(weak):
    return ("Install Guard: this would switch off a package-install protection (" + ", ".join(weak) + "). "
            "Install scripts stay off and new releases wait 7 days, so a hijacked release cannot run its install code. "
            "Run the same command without that setting. If a trusted native package needs its build step, "
            "use `npm rebuild <name> --ignore-scripts=false` for one of: " + ", ".join(sorted(REBUILD_OK)) + ".")


def npmrc_reason(found, days):
    return ("Install Guard: a project .npmrc switches off a package-install protection: " + "; ".join(found) + ". "
            f"Run the npm command again with `--ignore-scripts --min-release-age={days}` added. "
            "Do not edit or delete that .npmrc without asking the user.")


def young_reason(problems, days):
    lines = []
    for p in problems:
        if p["use"]:
            lines.append(f"{p['spec']} is {p['age_hours']} hours old (under {days} days). Use `{p['use']}` instead.")
        else:
            lines.append(f"{p['name']} has no release older than {days} days. It is too new to trust yet. "
                         "Choose an established package, or tell the user this one is needed.")
    return "Install Guard: " + " ".join(lines) + " New releases wait 7 days because hijacked versions are usually caught by then."


# ---------- job 3: tell the user once when a hijack-shaped release was skipped ----------

def lock_entries(folder):
    """{name: lockfile entry} from package-lock.json, or {}."""
    try:
        pkgs = json.loads((pathlib.Path(folder) / "package-lock.json").read_text()).get("packages") or {}
    except (OSError, ValueError):
        return {}
    return {k.rsplit("node_modules/", 1)[1]: v for k, v in pkgs.items() if k and "node_modules/" in k}


def build_hint(command, cwd):
    """After an install: packages that need their skipped install script, with the allowed command."""
    here, names = cwd, []
    for argv in segments(command):
        env, argv = unwrap(argv)
        if argv and argv[0] == "cd" and len(argv) > 1:
            target = pathlib.Path(os.path.expanduser(argv[1]))
            here = str(target if target.is_absolute() else pathlib.Path(here) / target)
            continue
        if not argv or os.path.basename(argv[0]) != "npm" or parse_npm(argv)["kind"] not in ("install", "ci"):
            continue
        for name, meta in lock_entries(here).items():
            if name in NEEDS_BUILD and meta.get("hasInstallScript") and name not in names:
                built = pathlib.Path(here) / "node_modules" / name / "build"
                ready = (pathlib.Path.home() / ".cache" / "puppeteer" / "chrome").exists() if name == "puppeteer" else built.exists()
                if not ready:
                    names.append(name)
    if not names:
        return None
    return ("Install Guard: install scripts are off on this machine, so " + ", ".join(names) +
            " is not ready yet. Its build step is allowed: run `npm rebuild " + " ".join(names) +
            " --ignore-scripts=false`.")


def lock_versions(folder):
    """{name: version} from package-lock.json, or {}."""
    try:
        pkgs = json.loads((pathlib.Path(folder) / "package-lock.json").read_text()).get("packages") or {}
    except (OSError, ValueError):
        return {}
    out = {}
    for key, meta in pkgs.items():
        if key and "node_modules/" in key and meta.get("version"):
            out[key.rsplit("node_modules/", 1)[1]] = meta["version"]
    return out


def snap_path(folder):
    return STATE / ("snap-" + hashlib.sha1(str(pathlib.Path(folder).resolve()).encode()).hexdigest()[:16] + ".json")


def snapshot(folder):
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        snap_path(folder).write_text(json.dumps(lock_versions(folder)))
    except OSError:
        pass


def skipped_release(name, installed, registry, days):
    """If the cooldown skipped a hijack-shaped release of this package, describe it."""
    doc = packument(name, registry)
    if not doc:
        return None
    cutoff = now() - datetime.timedelta(days=days)
    times, versions = doc.get("time") or {}, doc.get("versions") or {}
    base_t = vtuple(installed) if installed else None
    installed_t = parse_time(times.get(installed)) if installed else None
    ran = bool(base_t and installed_t and installed_t > cutoff)
    if ran:
        # The 7-day wait failed: the young release itself got installed. Compare it with the newest aged one on its line.
        newest = installed
        same_line = [v for v in aged_versions(doc, cutoff) if vtuple(v) and vtuple(v)[0] == base_t[0]]
        base = next(iter(same_line), None)
    else:
        skipped = []
        for v in versions:
            vt, t = vtuple(v), parse_time(times.get(v))
            if vt and t and t > cutoff and (base_t is None or vt > base_t):
                skipped.append((vt, v))
        if base_t:
            # Only the line npm would pick for a caret range: same major, and same minor below 1.0.
            skipped = [x for x in skipped if x[0][0] == base_t[0] and (base_t[0] > 0 or x[0][1] == base_t[1])]
        if not skipped:
            return None
        newest = max(skipped)[1]
        base = installed or next(iter(aged_versions(doc, cutoff)), None)
    new_meta, base_meta = versions.get(newest) or {}, versions.get(base) or {}
    new_deps = sorted(set(new_meta.get("dependencies") or {}) - set(base_meta.get("dependencies") or {}))
    dep_facts = []
    for dep in new_deps[:5]:
        dd = packument(dep, registry) or {}
        created = parse_time((dd.get("time") or {}).get("created"))
        dep_facts.append({"name": dep,
                          "age_days": round((now() - created).total_seconds() / 86400, 1) if created else None,
                          "install_script": any(has_script(m) for m in (dd.get("versions") or {}).values())})
    facts = {
        "package": name, "skipped": newest, "installed": installed, "ran": ran,
        "skipped_age_hours": round((now() - parse_time(times[newest])).total_seconds() / 3600),
        "new_dependencies": len(new_deps),
        "new_dependency_is_brand_new": any(d["age_days"] is not None and d["age_days"] < NEW_PACKAGE_DAYS for d in dep_facts),
        "new_dependency_runs_install_script": any(d["install_script"] for d in dep_facts),
        "release_adds_install_script": has_script(new_meta) and not has_script(base_meta),
    }
    # The Axios pattern: a new dependency that is brand new AND runs an install script.
    # A long-established scripted dependency (astro -> rolldown) is normal growth, not a hijack.
    if any(d["install_script"] and d["age_days"] is not None and d["age_days"] < NEW_PACKAGE_DAYS for d in dep_facts):
        return facts | {"deps": new_deps}
    return None


def ran_version(name, folder):
    """The version npx ran: the project's own copy first, else the newest copy in npx's cache."""
    copies = [pathlib.Path(folder) / "node_modules" / name / "package.json"]
    cache = pathlib.Path.home() / ".npm" / "_npx"
    if not copies[0].exists() and cache.is_dir():
        copies = sorted(cache.glob(f"*/node_modules/{name}/package.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in copies:
        try:
            return json.loads(path.read_text()).get("version")
        except (OSError, ValueError):
            continue
    return None


def after_install(command, cwd):
    """Return a message about skipped releases, or None."""
    days = cooldown_days()
    registry = registry_for(cwd)
    candidates, here = {}, cwd
    for argv in segments(command):
        env, argv = unwrap(argv)
        if argv and argv[0] == "cd" and len(argv) > 1:
            target = pathlib.Path(os.path.expanduser(argv[1]))
            here = str(target if target.is_absolute() else pathlib.Path(here) / target)
            continue
        if not argv or os.path.basename(argv[0]) not in ("npm", "npx"):
            continue
        npm = parse_npm(argv)
        if npm["kind"] not in ("install", "exec"):
            continue
        if npm["kind"] == "install" and not npm["global"]:
            try:
                before = json.loads(snap_path(here).read_text())
            except (OSError, ValueError):
                before = {}
            for name, version in lock_versions(here).items():
                if before.get(name) != version:
                    candidates[name] = version
        else:
            for spec in npm["specs"]:
                name, _ = split_spec(spec)
                if name:
                    candidates.setdefault(name, None if npm["global"] else ran_version(name, here))
    if not candidates:
        return None, {}
    import concurrent.futures
    deadline = time.monotonic() + POST_DEADLINE
    found = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    futures = [pool.submit(skipped_release, n, v, registry, days) for n, v in list(candidates.items())[:40]]
    timed_out = 0
    for f in futures:
        try:
            r = f.result(timeout=max(0.1, deadline - time.monotonic()))
        except Exception:
            r, timed_out = None, timed_out + 1
        if r:
            found.append(r)
    pool.shutdown(wait=False, cancel_futures=True)
    if not found:
        return None, {"checked": len(candidates), "timed_out": timed_out}
    seen_file = STATE / "notified.json"
    try:
        seen = set(json.loads(seen_file.read_text()))
    except (OSError, ValueError):
        seen = set()
    fresh = [f for f in found if f"{f['package']}@{f['skipped']}" not in seen]
    parts = []
    for f in found:
        if f["ran"]:
            got = "It RAN on this machine: the 7-day wait did not hold. Install scripts stayed off."
        elif f["installed"]:
            got = f"Your agent got {f['package']}@{f['installed']}."
        else:
            got = "Install Guard could not confirm which version ran."
        parts.append(f"{f['package']}@{f['skipped']} is {f['skipped_age_hours']} hours old and adds "
                     f"{', '.join(f['deps'])}, a brand-new package that runs an install script. {got}")
    if any(f["ran"] for f in found):
        title = "Install Guard: a suspicious release ran"
    elif all(f["installed"] for f in found):
        title = "Install Guard stopped a suspicious release"
    else:
        title = "Install Guard: check a suspicious release"
    message = f"{title}: " + " ".join(parts)
    if fresh:
        notify(title, " ".join(parts))
        try:
            STATE.mkdir(parents=True, exist_ok=True)
            seen_file.write_text(json.dumps(sorted(seen | {f"{f['package']}@{f['skipped']}" for f in fresh})))
        except OSError:
            pass
    return message, {"checked": len(candidates), "skipped": found, "notified": len(fresh)}


def notify(title, text):
    """One macOS notification. Tests set INSTALL_GUARD_NOTIFY_LOG to capture it instead."""
    sink = os.environ.get("INSTALL_GUARD_NOTIFY_LOG")
    if sink:
        with open(sink, "a") as f:
            f.write(json.dumps({"title": title, "text": text}) + "\n")
        return
    script = f"display notification {json.dumps(text[:240])} with title {json.dumps(title)}"
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
    except Exception:
        pass


# ---------- health ----------

def npm_version(npm="npm"):
    try:
        env = os.environ
        if npm != "npm":  # run a keg's npm with its own node first in PATH, as an agent would
            env = {**os.environ, "PATH": f"{os.path.dirname(npm)}:{os.environ.get('PATH', '')}"}
        out = subprocess.run([npm, "--version"], capture_output=True, text=True, timeout=10, env=env).stdout.strip()
        return tuple(int(x) for x in out.split(".")[:3])
    except Exception:
        return None


def keg_npms():
    """Every npm in a Homebrew Node keg (node@20, node@22, ...). Agents put these first in PATH,
    and npm 10 ignores min-release-age with no warning (seen after one week of real use)."""
    found = []
    for base in ("/opt/homebrew/opt", "/usr/local/opt"):
        for keg in sorted(pathlib.Path(base).glob("node@*")) if pathlib.Path(base).is_dir() else []:
            npm = keg / "bin" / "npm"
            if npm.exists():
                found.append(str(npm))
    return found


def doctor():
    """Print whether the protections are real on this machine. Exit 1 if not."""
    v = npm_version()
    ok_npm = v is not None and v >= MIN_NPM
    def get(key):
        try:
            return subprocess.run(["npm", "config", "get", key], capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            return "?"
    scripts, age = get("ignore-scripts"), get("min-release-age")
    rows = [
        (ok_npm, f"npm {'.'.join(map(str, v)) if v else '?'} (needs {'.'.join(map(str, MIN_NPM))}+ for the 7-day wait)"),
        (scripts == "true", f"ignore-scripts = {scripts}"),
        (age.isdigit() and int(age) >= 1, f"min-release-age = {age}"),
    ]
    for npm in keg_npms():
        kv = npm_version(npm)
        rows.append((kv is not None and kv >= MIN_NPM, f"{npm} {'.'.join(map(str, kv)) if kv else '?'}"))
    import pyguard
    rows += pyguard.doctor_rows(cooldown_days())
    for ok, text in rows:
        print(("ok    " if ok else "FAIL  ") + text)
    return 0 if all(ok for ok, _ in rows) else 1


def session_message():
    """At session start: say nothing if the last fire drill passed recently, else tell the agent."""
    fix = f"{shlex.quote(sys.executable)} {shlex.quote(str(ROOT / 'check.py'))} --fix"
    try:
        status = json.loads((STATE / "status.json").read_text())
        age = now() - datetime.datetime.fromisoformat(status["ts"])
    except (OSError, ValueError, KeyError):
        return f"Install Guard has no fire-drill result yet. Tell the user in one line and offer to run `{fix}`."
    if not status.get("ok"):
        failed = [c["name"] for c in status.get("checks", []) if not c.get("ok")]
        return (f"Install Guard's last fire drill FAILED ({', '.join(failed)}). Supply-chain protection may be off. "
                f"Tell the user in one line and offer to run `{fix}`.")
    if age > datetime.timedelta(days=3):
        return (f"Install Guard's fire drill has not run for {age.days} days (it should run daily). "
                f"Tell the user in one line and offer to run `{fix}`.")
    return None


# ---------- hook entry ----------

def log(entry):
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def main():
    if "--doctor" in sys.argv:
        sys.exit(doctor())
    if len(sys.argv) >= 4 and sys.argv[1] == "--after":
        t0 = time.monotonic()
        try:
            message, facts = after_install(sys.argv[3], sys.argv[2])
            log({"ts": now().isoformat(timespec="seconds"), "hook": "after", "cwd": sys.argv[2],
                 "command": sys.argv[3][:300], "decision": "post", "ms": round((time.monotonic() - t0) * 1000), **facts})
        except Exception as error:
            log({"ts": now().isoformat(timespec="seconds"), "hook": "after", "error": f"{type(error).__name__}: {error}"[:200]})
        os._exit(0)  # do not wait for registry fetches that ran past the deadline
    t0 = time.monotonic()
    try:
        event = json.load(sys.stdin)
    except Exception:
        return
    hook = event.get("hook_event_name", "PreToolUse")
    tool = event.get("tool_name", "Bash")
    tin = event.get("tool_input") or {}
    cwd = event.get("cwd") or os.getcwd()
    shadow = bool(os.environ.get("INSTALL_GUARD_SHADOW")) or (STATE / "shadow").exists()
    entry = {"ts": now().isoformat(timespec="seconds"), "hook": hook, "tool": tool, "cwd": cwd,
             "host": "codex" if "--host=codex" in sys.argv else "claude", "shadow": shadow}
    try:
        if hook == "SessionStart":
            message = session_message()
            if message:
                entry.update(decision="session-warning", warning=message)
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": message}}))
            return
        if hook == "PostToolUseFailure":
            command = tin.get("command", "")
            if tool != "Bash" or not re.search(r"\b(pip3?|uvx?)\b", command):
                return
            import pyguard
            output = " ".join(str(event.get(k) or "") for k in ("error", "tool_result", "tool_response", "tool_output"))
            hint = pyguard.failure_hint(command, output, cooldown_days())
            entry.update(command=command[:300], decision="failure", build_hint=hint, event_keys=sorted(event))
            if hint:
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUseFailure", "additionalContext": hint}}))
            return
        if hook == "PostToolUse":
            command = tin.get("command", "")
            if tool != "Bash" or not re.search(r"\b(npm|npx)\b", command):
                return
            hint = build_hint(command, cwd)
            if hint:
                entry.update(build_hint=hint)
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": hint}}))
            if os.environ.get("INSTALL_GUARD_FOREGROUND"):
                message, facts = after_install(command, cwd)
                entry.update(command=command[:300], decision="post", **facts)
            else:
                # The agent never waits for this check. The notification is the channel.
                subprocess.Popen([sys.executable, __file__, "--after", cwd, command], start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                entry.update(command=command[:300], decision="post-started")
            return
        if tool == "Bash":
            command = tin.get("command", "")
            result = decide_command(command, cwd)
            if result is None:
                return
            decision, reason, facts = result
            entry.update(command=command[:300])
        else:
            path = tin.get("file_path") or ""
            if os.path.basename(path) not in (".npmrc", "pip.conf", "pip.ini", "uv.toml", "pyproject.toml") \
                    and "Application Support/pip" not in path:
                return
            text = tin.get("content") or tin.get("new_string") or "\n".join(e.get("new_string", "") for e in tin.get("edits") or [])
            old = tin.get("old_string") or "\n".join(e.get("old_string", "") for e in tin.get("edits") or [])
            decision, reason, facts = decide_edit(path, text, old, full=tool == "Write")
            entry.update(file=path)
        entry.update(decision=decision, reason=reason, **facts)
        if decision == "deny" and not shadow:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                     "permissionDecisionReason": reason}}))
    except Exception as error:
        entry.update(decision="allow", error=f"{type(error).__name__}: {error}"[:200], fail_open=True)
    finally:
        if "decision" in entry:
            entry["ms"] = round((time.monotonic() - t0) * 1000)
            log(entry)


if __name__ == "__main__":
    main()
