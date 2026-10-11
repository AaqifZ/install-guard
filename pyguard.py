"""Install Guard rules for pip and uv. install_guard.py imports this only when a command mentions them.

pip and uv do the protecting, from their user config files:
  ~/.config/pip/pip.conf   only-binary = :all:      no source builds, so no package code runs at install
                           uploaded-prior-to = P7D  nothing younger than 7 days
  ~/.config/uv/uv.toml     exclude-newer = "7 days"
                           [pip] only-binary = [":all:"]
These rules keep that config switched on and keep the agent moving. Uncertain cases allow.
"""
import datetime
import json
import os
import pathlib
import re
import sys

PIP_CONF = pathlib.Path.home() / ".config" / "pip" / "pip.conf"
UV_TOML = pathlib.Path.home() / ".config" / "uv" / "uv.toml"
CONFIG_NAMES = {"pip.conf", "pip.ini", "uv.toml"}

PIP_VALUE = {"-i", "--index-url", "--extra-index-url", "-r", "--requirement", "-c", "--constraint", "--no-binary",
             "--only-binary", "--uploaded-prior-to", "--target", "-t", "--prefix", "--root", "--python", "--platform",
             "--python-version", "--implementation", "--abi", "-f", "--find-links", "--trusted-host", "--cache-dir",
             "--log", "--proxy", "--retries", "--timeout", "--src", "--upgrade-strategy", "--progress-bar",
             "--config-settings", "-C", "--report", "--exists-action", "--keyring-provider", "--cert", "--client-cert",
             "--use-feature", "--use-deprecated", "--group"}
UV_VALUE = {"--python", "-p", "--index-url", "-i", "--extra-index-url", "--index", "--default-index", "-r",
            "--requirement", "-c", "--constraint", "--overrides", "--no-binary", "--only-binary", "--exclude-newer",
            "--exclude-newer-package", "--find-links", "-f", "--cache-dir", "--python-platform", "--python-version",
            "--target", "--prefix", "--with", "-w", "--from", "--directory", "--project", "--resolution", "--prerelease",
            "--index-strategy", "--keyring-provider", "--config-file", "--link-mode", "--group", "--extra",
            "--upgrade-package", "-P", "--reinstall-package", "--no-build-package", "--no-binary-package",
            "--refresh-package", "--torch-backend", "--config-setting", "-C", "--with-requirements", "--optional"}


def mentions(command):
    return bool(re.search(r"\b(pip3?(\.\d+)?|uvx?)\b|\bPIP_|\bUV_|pip\.conf|pip\.ini|uv\.toml|pyproject\.toml", command))


def parse(argv):
    """Describe a pip/uv call, or None. Returns tool, sub, flags, specs."""
    base = os.path.basename(argv[0])
    if re.fullmatch(r"pip(3(\.\d+)?)?", base):
        tool, rest = "pip", argv[1:]
    elif re.fullmatch(r"python(3(\.\d+)?)?", base) and argv[1:3] == ["-m", "pip"]:
        tool, rest = "pip", argv[3:]
    elif base == "uv" and len(argv) > 1:
        if argv[1] == "pip":
            tool, rest = "uv-pip", argv[2:]
        elif argv[1] == "tool" and len(argv) > 2 and argv[2] in ("run", "install"):
            tool, rest = "uvx" if argv[2] == "run" else "uv", [argv[2]] + argv[3:]
        else:
            tool, rest = "uv", argv[1:]
    elif base == "uvx":
        tool, rest = "uvx", ["run"] + argv[1:]
    else:
        return None
    # uv-pip takes `--no-binary <names>`. uv, uv run, uv tool and uvx take a bare `--no-binary` that means every package.
    values = PIP_VALUE if tool == "pip" else UV_VALUE if tool == "uv-pip" else UV_VALUE - {"--no-binary"}
    words, flags, i = [], [], 0
    while i < len(rest):
        t = rest[i]
        if t.startswith("-") and t != "-":
            if t in values and i + 1 < len(rest):
                flags.append(f"{t}={rest[i + 1]}")
                i += 1
            else:
                flags.append(t)
        else:
            words.append(t)
        i += 1
    sub = words[0] if words else ""
    specs = words[1:] if tool != "uvx" else words[1:2]
    return {"tool": tool, "sub": sub, "flags": flags, "specs": specs}


# ---------- durations and dates ----------

def duration_days(text):
    """'P7D', 'PT24H', '7 days', '1 week', '24 hours' -> days as a float. None if not a duration."""
    t = text.strip().strip("'\"").lower()
    m = re.fullmatch(r"p(?:(\d+)w)?(?:(\d+)d)?(?:t(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?)?", t)
    if m and any(m.groups()):
        w, d, h, mi, s = (int(x or 0) for x in m.groups())
        return w * 7 + d + h / 24 + mi / 1440 + s / 86400
    total, found = 0.0, False
    # Long and compact units, as uv accepts them: "7 days", "1h", "30m", "2w", "1mo".
    units = {"y": 365, "mo": 30, "w": 7, "d": 1, "h": 1 / 24, "m": 1 / 1440, "s": 1 / 86400}
    for n, unit in re.findall(r"(\d+(?:\.\d+)?)\s*(years?|yrs?|y|months?|mo|weeks?|w|days?|d|hours?|hrs?|h|"
                              r"minutes?|mins?|m|seconds?|secs?|s)\b", t):
        found = True
        key = "mo" if unit.startswith("mo") else unit[0]
        total += float(n) * units[key]
    return total if found else None


def weak_time(value, days):
    """True if a cutoff value lets in releases younger than `days`."""
    v = value.strip().strip("'\"")
    if v.lower() in ("false", "0", "none", ""):
        return True
    d = duration_days(v)
    if d is not None:
        return d < days
    try:
        when = datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        return when > datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    except ValueError:
        return False  # unknown form: allow


# ---------- job 1: protections stay on ----------

def weak_call(call, env, days):
    found = []
    for f in call["flags"]:
        key, _, value = f.partition("=")
        low = value.lower()
        if key == "--no-binary" and ":all:" in low:
            found.append(f)
        elif key == "--no-binary" and call["tool"] in ("uv", "uvx") and low in ("", "true", "1"):
            found.append(f)
        elif key == "--only-binary" and ":none:" in low:
            found.append(f)
        elif key in ("--uploaded-prior-to", "--exclude-newer") and weak_time(value, days):
            found.append(f)
        elif key == "--exclude-newer-package" and "=" in value and weak_time(value.split("=", 1)[1], days):
            found.append(f)
        elif key in ("--isolated", "--no-config", "--config-file"):
            found.append(f)
    for key, value in env.items():
        k, low = key.upper(), value.lower()
        if k in ("PIP_CONFIG_FILE", "UV_CONFIG_FILE"):
            found.append(f"{key}={value}")
        elif k in ("PIP_ISOLATED_MODE", "UV_NO_CONFIG") and low not in ("", "0", "false", "no"):
            found.append(f"{key}={value}")
        elif k == "PIP_NO_BINARY" and ":all:" in low:
            found.append(f"{key}={value}")
        elif k == "PIP_ONLY_BINARY" and ":none:" in low:
            found.append(f"{key}={value}")
        elif k in ("PIP_UPLOADED_PRIOR_TO", "UV_EXCLUDE_NEWER") and weak_time(value, days):
            found.append(f"{key}={value}")
        elif k == "UV_NO_BINARY" and low not in ("", "0", "false", "no"):
            found.append(f"{key}={value}")
        elif k == "XDG_CONFIG_HOME" and os.path.normpath(os.path.expanduser(value.replace("$HOME", "~").strip("'\""))) != \
                str(pathlib.Path.home() / ".config"):
            found.append(f"{key}={value}")  # pip and uv would read their config from somewhere else
    if call["tool"] == "pip" and call["sub"] == "config":
        args = " ".join(call["specs"]).replace("=", " ").split()
        action = args[0] if args else ""
        if action in ("set", "unset", "edit") and any(re.search(r"only-binary|no-binary|uploaded-prior-to", a) for a in args):
            ok = action == "set" and len(args) == 3 and (
                (args[1].endswith("only-binary") and args[2] == ":all:") or
                (args[1].endswith("uploaded-prior-to") and not weak_time(args[2], days)))
            if not ok:
                found.append("pip config " + " ".join(call["specs"]))
    return found


WEAK_TEXT = re.compile(r"(only-binary\s*=\s*\[?\s*[\"']?:none:|no-binary\s*=\s*(\[?\s*[\"']?:all:|true)|"
                       r"no-build\s*=\s*false|(uploaded-prior-to|exclude-newer)\s*=\s*(\"[^\"\n]*\"|[^\s'\"\\]+))", re.I)


def weak_config_text(text, days):
    """Lines in pip.conf / uv.toml / pyproject [tool.uv] text that switch a protection off."""
    found = []
    for m in WEAK_TEXT.finditer(text or ""):
        if m.group(3) is not None and not weak_time(m.group(4), days):
            continue
        found.append(m.group(0).strip())
    return found


def weak_write(command, days):
    """A shell command that writes a weakening line into a pip or uv config file."""
    if not re.search(r"(>>?|\btee\b|\bsed\b[^;&|]*\s-i)[^;&|]*(pip\.conf|pip\.ini|uv\.toml|pyproject\.toml)", command):
        return []
    return weak_config_text(command, days)


def project_weakness(cwd, days):
    """uv.toml or pyproject.toml [tool.uv] in cwd or a parent that switches a protection off."""
    found, path, home = [], pathlib.Path(cwd), pathlib.Path.home()
    for folder in [path, *path.parents]:
        for name in ("uv.toml", "pyproject.toml"):
            f = folder / name
            if not f.is_file() or f == UV_TOML:
                continue
            try:
                text = f.read_text()
            except OSError:
                continue
            if name == "pyproject.toml":
                m = re.search(r"^\[tool\.uv\]\s*$(.*?)(?=^\[(?!tool\.uv)|\Z)", text, re.M | re.S)
                text = m.group(1) if m else ""
            found += [f"{f}: {line}" for line in weak_config_text(text, days)]
        if folder == home:
            break
    return found


# ---------- job 2: unstick the agent ----------

def ptuple(v):
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.post\d+)?", v or "")
    return tuple(int(x or 0) for x in m.groups()) if m else None


def json_api(call):
    """PyPI JSON API base for this call's index."""
    for f in call["flags"]:
        key, _, value = f.partition("=")
        if key in ("-i", "--index-url", "--default-index"):
            return re.sub(r"/simple/?$", "/pypi", value.rstrip("/"))
    env = os.environ.get("PIP_INDEX_URL") or os.environ.get("UV_DEFAULT_INDEX") or os.environ.get("UV_INDEX_URL")
    return re.sub(r"/simple/?$", "/pypi", env.rstrip("/")) if env else "https://pypi.org/pypi"


def release_times(name, base, timeout=4.0):
    """{version: first upload time} from the JSON API, or None."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{base}/{name}/json", timeout=timeout) as r:
            doc = json.load(r)
    except Exception:
        return None
    out = {}
    for v, files in (doc.get("releases") or {}).items():
        times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
        if times:
            out[v] = datetime.datetime.fromisoformat(min(times).replace("Z", "+00:00"))
    return out


def young_pins(call, days):
    """Exact pins younger than the cooldown, each with an older version to use."""
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    sep = "@" if call["tool"] == "uvx" else "=="
    problems = []
    for spec in call["specs"]:
        m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|@)\s*([0-9][0-9.]*(?:\.post\d+)?)", spec)
        if not m or not ptuple(m.group(4)):
            continue
        name, extras, version = m.group(1), m.group(2) or "", m.group(4)
        times = release_times(name, json_api(call))
        if not times or version not in times or times[version] <= cutoff:
            continue
        old = sorted((ptuple(v), v) for v, t in times.items() if t <= cutoff and ptuple(v))
        same = [v for t, v in old if t[0] == ptuple(version)[0]]
        pick = (same or [v for _, v in old] or [None])[-1]
        problems.append({"spec": spec, "name": name, "age_hours": round((datetime.datetime.now(datetime.timezone.utc) - times[version]).total_seconds() / 3600),
                         "use": f"{name}{extras}{sep}{pick}" if pick else None})
    return problems


# ---------- decisions ----------

def decide(argv, env, cwd, days):
    """(decision, reason, facts) for one pip/uv call, or None if it is not one."""
    call = parse(argv)
    if not call:
        return None
    facts = {"py_tool": call["tool"]}
    weak = weak_call(call, env, days)
    if weak:
        return "deny", off_reason(weak, days), facts
    installing = call["sub"] in ("install", "add", "sync", "run", "download", "lock") or call["tool"] == "uvx"
    if not installing:
        return "allow", None, facts
    if call["tool"] != "pip":
        rc = project_weakness(cwd, days)
        overridden = any(f.startswith("--exclude-newer=") and not weak_time(f.split("=", 1)[1], days) for f in call["flags"])
        if rc and not overridden:
            return "deny", ("Install Guard: a project uv setting switches off a package-install protection: " + "; ".join(rc) +
                            f'. Run the uv command again with `--exclude-newer "{days} days"` added. '
                            "Do not edit that file without asking the user."), facts
    problems = young_pins(call, days)
    if problems:
        facts["problems"] = problems
        lines = []
        for p in problems:
            if p["use"]:
                lines.append(f"{p['spec']} is {p['age_hours']} hours old (under {days} days). Use `{p['use']}` instead.")
            else:
                lines.append(f"{p['name']} has no release older than {days} days. It is too new to trust yet. "
                             "Choose an established package, or tell the user this one is needed.")
        return "deny", "Install Guard: " + " ".join(lines), facts
    return "allow", None, facts


def off_reason(weak, days):
    return ("Install Guard: this would switch off a Python package-install protection (" + ", ".join(weak) + "). "
            f"pip and uv only install prebuilt wheels and nothing younger than {days} days, so a hijacked release cannot run its install code. "
            "Run the same command without that setting. If one well-known package has no wheel, build only that one: "
            "`pip install <name> --no-binary <name>` (`uv pip install` takes the same flag; uv, uv run, uv tool and uvx "
            "take `--no-binary-package <name>`).")


def decide_edit(path, text, days):
    name = os.path.basename(path or "")
    if name in CONFIG_NAMES:
        weak = weak_config_text(text, days)
    elif name == "pyproject.toml" and "tool.uv" in (text or "") or name == "pyproject.toml" and re.search(r"exclude-newer|no-build|no-binary|only-binary", text or ""):
        weak = weak_config_text(text, days)
    else:
        return None
    return ("deny", off_reason(weak, days), {}) if weak else ("allow", None, {})


def failure_hint(command, output, days=7):
    """After a failed pip/uv install: say why (too new, or no wheel) and give the allowed command."""
    m = re.search(r"No matching distribution found for ([A-Za-z0-9][A-Za-z0-9._-]*)", output or "") or \
        re.search(r"Wheels are required for `([A-Za-z0-9][A-Za-z0-9._-]*)`", output or "")
    if not m:
        return None
    name = m.group(1)
    tool = "uv pip install" if re.search(r"\buv\b", command) else "pip install"
    idx = re.search(r"(?:-i|--index-url|--default-index)[ =](\S+)", command)
    base = re.sub(r"/simple/?$", "/pypi", idx.group(1).rstrip("/")) if idx else "https://pypi.org/pypi"
    import urllib.request
    try:
        with urllib.request.urlopen(f"{base}/{name}/json", timeout=4) as r:
            releases = (json.load(r).get("releases") or {})
    except Exception:
        return None  # unknown package or no network: npm/pip's own error says enough
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    old = {}
    for v, files in releases.items():
        times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
        if times and ptuple(v) and datetime.datetime.fromisoformat(min(times).replace("Z", "+00:00")) <= cutoff:
            old[ptuple(v)] = (v, files)
    if not old:
        return (f"Install Guard: every release of {name} is under {days} days old, so the {days}-day wait skips it. "
                "Hijacked releases are usually caught within days. Choose an established package, or tell the user this one is needed.")
    v, files = old[max(old)]
    if not any(f.get("packagetype") == "bdist_wheel" for f in files):
        why = f"{name} {v} ships only source code, no prebuilt wheel."
    else:
        why = f"{name} {v} has wheels, but maybe none for this Python version."
    return (f"Install Guard: {why} Source builds are off on this machine, because a source build runs the package's own code "
            f"during install. If {name} is a well-known package, build just that one: `{tool} {name} --no-binary {name}`.")


def doctor_rows(days):
    rows = []
    try:
        pip_text = PIP_CONF.read_text()
    except OSError:
        pip_text = ""
    try:
        uv_text = UV_TOML.read_text()
    except OSError:
        uv_text = ""
    m = re.search(r"uploaded-prior-to\s*=\s*(\S+)", pip_text)
    rows.append((bool(re.search(r"only-binary\s*=\s*:all:", pip_text)), f"pip only-binary = :all: ({PIP_CONF})"))
    rows.append((bool(m) and not weak_time(m.group(1), days), f"pip uploaded-prior-to = {m.group(1) if m else 'missing'}"))
    m = re.search(r"exclude-newer\s*=\s*\"([^\"]+)\"", uv_text)
    rows.append((bool(m) and not weak_time(m.group(1), days), f"uv exclude-newer = {m.group(1) if m else 'missing'} ({UV_TOML})"))
    rows.append((bool(re.search(r"only-binary\s*=\s*\[\s*\":all:\"", uv_text)), "uv [pip] only-binary = [\":all:\"]"))
    shadow = pathlib.Path.home() / "Library" / "Application Support" / "pip"
    if sys.platform == "darwin":
        rows.append((not shadow.exists(), f"{shadow} absent (if it exists, pip ignores {PIP_CONF})"))
    return rows
