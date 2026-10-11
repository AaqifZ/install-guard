"""Offline tests for job 1: the agent cannot switch the install protections off.

Run: python tests/test_rules.py
The registry points at a closed port, so no network is used. Registry failures allow.
Dangerous commands are strings only. Never execute them.
"""
import os
import pathlib
import sys
import tempfile

os.environ["npm_config_registry"] = "http://127.0.0.1:9/"
os.environ["HOME"] = HOME = tempfile.mkdtemp()  # a throwaway HOME: the rules read ~ but must never see the real one
os.environ["INSTALL_GUARD_STATE"] = tempfile.mkdtemp()
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import install_guard as g  # noqa: E402

CWD = tempfile.mkdtemp()

DENY = [
    "npm i left-pad --ignore-scripts=false",
    "npm i left-pad --ignore-scripts false",
    "npm install --no-ignore-scripts",
    "npm_config_ignore_scripts=false npm i left-pad",
    "NPM_CONFIG_IGNORE_SCRIPTS=false npm ci",
    "env npm_config_ignore_scripts=false npm install",
    "export npm_config_ignore_scripts=false && npm i",
    "export npm_config_min_release_age=0; npm i left-pad",
    "npm config set ignore-scripts false",
    "npm config set ignore-scripts=false",
    "npm set ignore-scripts false",
    "npm config delete ignore-scripts",
    "npm config delete min-release-age",
    "npm config set min-release-age 0",
    "npm config set min-release-age=2",
    "npm i left-pad --min-release-age=1",
    "npm i left-pad --min-release-age 0",
    "npm i left-pad --before=2026-10-04",
    "echo 'ignore-scripts=false' >> ~/.npmrc",
    "printf 'min-release-age=0\\n' > .npmrc",
    "echo ignore-scripts=false | tee -a .npmrc",
    "sed -i '' 's/ignore-scripts=true/ignore-scripts=false/' ~/.npmrc",
    "cd /tmp && npm i left-pad --ignore-scripts=false",
    "npm rebuild plain-crypto-js --ignore-scripts=false",
    "npm rebuild --ignore-scripts=false",
    "sudo npm i -g left-pad --ignore-scripts=false",
    "npx --ignore-scripts=false some-cli",
    "npm exec --min-release-age=0 -- some-cli",
    "npm ci && npm i x --no-ignore-scripts",
    "bash -c 'npm i left-pad --ignore-scripts=false'",
    "sh -c \"npm config set ignore-scripts false\"",
    "eval npm i left-pad --min-release-age=0",
    "zsh -lc 'npm i x --no-ignore-scripts'",
    # pip and uv
    "pip install requests --no-binary :all:",
    "pip install requests --only-binary=:none:",
    "pip install requests --uploaded-prior-to P1D",
    "pip install --isolated requests",
    "python3 -m pip install --no-binary=:all: requests",
    "PIP_CONFIG_FILE=/dev/null pip install requests",
    "PIP_NO_BINARY=:all: pip3 install requests",
    "export PIP_CONFIG_FILE=/dev/null && pip install x",
    "pip config unset install.uploaded-prior-to",
    "pip config set global.only-binary :none:",
    "uv pip install requests --exclude-newer false",
    "uv pip install requests --exclude-newer '1 hour'",
    "uv pip install requests --exclude-newer 1h",
    "UV_EXCLUDE_NEWER=30m uv sync",
    "uv add requests --no-config",
    "UV_EXCLUDE_NEWER=false uv sync",
    "UV_NO_CONFIG=1 uv pip install requests",
    "uvx --exclude-newer false ruff",
    "echo 'only-binary = :none:' >> ~/.config/pip/pip.conf",
    "printf 'exclude-newer = false\\n' > ~/.config/uv/uv.toml",
    "bash -c 'pip install x --no-binary :all:'",
    "corepack pnpm install",
    "corepack enable",
    "pnpm add left-pad",
    "yarn add left-pad",
    "bunx cowsay hi",
    "npx pnpm install",
    "npx --yes yarn install",
    "cd /tmp && pnpm i",
    # another npm config file would drop the protections
    "npm i left-pad --userconfig /tmp/empty",
    "npm install --globalconfig=/tmp/x",
    "npm_config_userconfig=/dev/null npm i left-pad",
    "NPM_CONFIG_GLOBALCONFIG=/tmp/x npm ci",
    "export npm_config_userconfig=/dev/null; npm i left-pad",
    "export NPM_CONFIG_USERCONFIG=/tmp/x && npm install",
    # delete, truncate or replace a protected config file
    "rm ~/.npmrc",
    "rm -f $HOME/.npmrc",
    "mv ~/.npmrc ~/.npmrc.off",
    ": > ~/.npmrc",
    "> ~/.npmrc",
    "truncate -s 0 ~/.npmrc",
    "echo registry=https://registry.npmjs.org/ > ~/.npmrc",
    "cp /dev/null ~/.npmrc",
    "cd ~ && rm .npmrc",
    "rm ~/.config/pip/pip.conf",
    "rm -rf ~/.config/pip",
    "mv ~/.config/uv/uv.toml /tmp/",
    "cat /dev/null > ~/.config/uv/uv.toml",
    "sed -i '' '/only-binary/d' ~/.config/pip/pip.conf",
    # an npm too old for min-release-age
    "npm install -g npm@10.8.2",
    "npm i -g npm@10",
    "npm install -g npm@11.9.0",
    "npm install -g npm@latest-10",
    "npx npm@10 install",
    # a bare --no-binary means every package for uv, uv run, uv tool and uvx
    "uvx --no-binary ruff",
    "uv tool install --no-binary ruff",
    "uv tool run --no-binary ruff",
    "uv run --no-binary pytest",
    # pip and uv read their config from XDG_CONFIG_HOME
    "XDG_CONFIG_HOME=/tmp/cfg uv pip install requests",
    "XDG_CONFIG_HOME=/tmp pip install requests",
    "export XDG_CONFIG_HOME=/tmp/x && uv sync",
    # pip on macOS ignores ~/.config/pip/pip.conf once this folder exists
    "mkdir -p ~/Library/Application\\ Support/pip",
    'mkdir -p "$HOME/Library/Application Support/pip"',
    "touch ~/Library/Application\\ Support/pip/pip.conf",
    "echo '[global]' > ~/Library/Application\\ Support/pip/pip.conf",
]

ALLOW = [
    "npm ci",
    "npm install",
    "npm run build",
    "npm test",
    "npm config get ignore-scripts",
    "npm config set ignore-scripts true",
    "npm config set min-release-age 14",
    "npm rebuild sharp --ignore-scripts=false",
    "npm rebuild esbuild sharp --ignore-scripts=false",
    "npm i left-pad --ignore-scripts",
    "git commit -m 'docs: never set ignore-scripts=false in .npmrc'",
    "grep ignore-scripts ~/.npmrc",
    "cat .npmrc",
    "echo 'registry=https://registry.npmjs.org/' >> .npmrc",
    "ls node_modules | head",
    "pip install requests",
    "bash -c 'npm ci && npm run build'",
    "pip install requests",
    "pip install reportlab pdfplumber pypdf",
    "pip install oldpkg --no-binary oldpkg",
    "python3 -m pip install -r requirements.txt",
    "uv pip install requests",
    "uv add httpx",
    "uv sync",
    "uvx ruff check .",
    "pip install x --uploaded-prior-to P14D",
    "uv pip install x --exclude-newer '30 days'",
    "uv pip install x --exclude-newer 2w",
    "pip config set install.uploaded-prior-to P10D",
    "pip list",
    "cat ~/.config/pip/pip.conf",
    "uv run pytest",
    "cat pnpm-lock.yaml",
    "git commit -m 'switch from pnpm to npm'",
    "rg yarn src",
    "rm .npmrc",
    "cp ~/.npmrc /tmp/npmrc.bak",
    "echo 'save-exact=true' >> ~/.npmrc",
    "npm ci 2>&1 > build.log",
    "npm install -g npm@11.20.0",
    "npm install -g npm@latest",
    "npm i -g npm@11",
    "uvx --no-binary-package ruff ruff",
    "uv pip install x --no-binary x",
    "XDG_CONFIG_HOME=$HOME/.config uv sync",
    "ls ~/Library/Application\\ Support",
]

EDITS = [
    ("/home/x/.config/pip/pip.conf", "[global]\nonly-binary = :none:\n", "deny"),
    ("/home/x/.config/uv/uv.toml", 'exclude-newer = "1 day"\n', "deny"),
    ("/p/pyproject.toml", '[project]\nname="a"\n[tool.uv]\nexclude-newer = false\n', "deny"),
    ("/p/pyproject.toml", '[project]\nname="a"\ndependencies=["requests"]\n', "allow"),
    ("/home/x/.config/uv/uv.toml", 'exclude-newer = "14 days"\n', "allow"),
    (".npmrc", "ignore-scripts=false\n", "deny"),
    ("/x/.npmrc", "registry=https://example.com\nmin-release-age=0\n", "deny"),
    ("/x/.npmrc", "registry=https://example.com\n", "allow"),
    ("/x/.npmrc", "min-release-age=14\n", "allow"),
    ("/x/notes.md", "ignore-scripts=false\n", "allow"),
    # (path, new text, want, old text, whole-file Write)
    ("~/.npmrc", "registry=https://example.com\n", "deny", None, True),
    ("~/.npmrc", "ignore-scripts=true\nmin-release-age=7\nsave-exact=true\n", "allow", None, True),
    ("~/.npmrc", "", "deny", "ignore-scripts=true\n", False),
    ("~/.npmrc", "save-exact=true\n", "allow", "registry=https://example.com\n", False),
    ("~/.config/pip/pip.conf", "[global]\nindex-url = https://example.com/simple\n", "deny", None, True),
    ("~/.config/uv/uv.toml", "[pip]\n", "deny", 'exclude-newer = "7 days"\n[pip]\n', False),
    ("~/Library/Application Support/pip/pip.conf", "[global]\nonly-binary = :all:\n", "deny", None, True),
]


def bash(command):
    """The hook's own Bash decision. Every deny must hand the agent a command to run instead."""
    result = g.decide_command(command, CWD) or ("allow", None, {})
    if result[0] == "deny" and "`" not in (result[1] or ""):
        return "deny without a next command"
    return result[0]


def main():
    failures = []
    for c in DENY:
        if bash(c) != "deny":
            failures.append(("should deny", c))
    for c in ALLOW:
        if bash(c) != "allow":
            failures.append(("should allow", c))
    for path, text, want, *rest in EDITS:
        old, full = rest if rest else (None, False)
        if g.decide_edit(os.path.expanduser(path), text, old, full)[0] != want:
            failures.append((f"edit should {want}", f"{path} {text!r}"))
    # A weak project .npmrc is caught, and the suggested flags clear it.
    proj = pathlib.Path(tempfile.mkdtemp())
    (proj / ".npmrc").write_text("ignore-scripts=false\n")
    if g.decide_bash("npm ci", str(proj))[0] != "deny":
        failures.append(("should deny", "npm ci with a weak project .npmrc"))
    if g.decide_bash("npm ci --ignore-scripts --min-release-age=7", str(proj))[0] != "allow":
        failures.append(("should allow", "npm ci with the suggested override flags"))
    if g.decide_bash(f"cd {proj} && npm ci", CWD)[0] != "deny":
        failures.append(("should deny", "cd into a project with a weak .npmrc"))
    proj2 = pathlib.Path(tempfile.mkdtemp())
    (proj2 / "pyproject.toml").write_text('[project]\nname = "a"\n[tool.uv]\nexclude-newer = "2 hours"\n')
    if g.decide_bash("uv sync", str(proj2))[0] != "deny":
        failures.append(("should deny", "uv sync with a weak [tool.uv] exclude-newer"))
    if g.decide_bash('uv sync --exclude-newer "7 days"', str(proj2))[0] != "allow":
        failures.append(("should allow", "uv sync with the suggested override"))
    # Other package managers get a working npm command, not a dead end.
    for cmd, want in (("pnpm add left-pad -D", "`npm install left-pad -D`"), ("corepack yarn dlx cowsay", "`npx cowsay`"),
                      ("pnpm run build", "`npm run build`")):
        reason = g.decide_bash(cmd, CWD)[1] or ""
        if want not in reason:
            failures.append((f"should suggest {want}", cmd))
    total = len(DENY) + len(ALLOW) + len(EDITS) + 8
    for why, c in failures:
        print(f"FAIL  {why}: {c}")
    print(f"{total - len(failures)}/{total} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
