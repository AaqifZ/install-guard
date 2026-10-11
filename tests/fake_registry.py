"""A tiny local npm registry that replays the Axios attack with a harmless payload.

The bad packages only write marker files and call this server's /c2 path.
Publish times are relative to now, so "2 hours old" stays true on every run.
Stdlib only. Run directly to serve on 127.0.0.1:4873.
"""
import base64
import datetime
import hashlib
import io
import json
import pathlib
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOUR = datetime.timedelta(hours=1)
DAY = datetime.timedelta(days=1)

# name -> list of (version, age, dependencies, files, scripts)
# A postinstall script is the Axios path. index.js payloads model a scriptless attack.
STAGE = '''const fs=require("fs"),http=require("http");
fs.writeFileSync(process.env.MARKER_DIR_OVERRIDE||"{marker}/{what}","ran");
http.get("http://127.0.0.1:{port}/c2/{what}").on("error",()=>{{}});
'''


def catalogue(marker, port):
    def payload(what):
        return STAGE.format(marker=marker, port=port, what=what)

    clean = "module.exports = {};\n"
    CLI = "#!/usr/bin/env node\nrequire('./index.js');\n"
    return {
        # The trusted library. 1.14.1 and 0.30.4 are the hijacked releases.
        "axios": [
            ("0.30.3", 70 * DAY, {}, {"index.js": clean}, {}),
            ("1.14.0", 35 * DAY, {}, {"index.js": clean}, {}),
            ("0.30.4", 2 * HOUR, {"plain-crypto-js": "^4.2.1"}, {"index.js": clean}, {}),
            ("1.14.1", 2 * HOUR, {"plain-crypto-js": "^4.2.1"}, {"index.js": clean}, {}),
        ],
        # The dependency nobody asked for. Brand new, runs an install script.
        "plain-crypto-js": [
            ("4.2.1", 3 * HOUR, {}, {"index.js": clean, "setup.js": payload("install-script-ran")},
             {"postinstall": "node setup.js"}),
        ],
        # A normal tool that depends on axios ^1.14.0: the transitive path.
        "site-tool": [
            ("2.0.0", 60 * DAY, {"axios": "^1.14.0"}, {"index.js": "require('axios');\n"}, {}),
        ],
        # A legitimate fast-moving package with a long-standing install script (like esbuild).
        "fastbuild": [
            ("0.25.0", 20 * DAY, {}, {"index.js": clean, "install.js": "\n"}, {"postinstall": "node install.js"}),
            ("0.25.1", 1 * DAY, {}, {"index.js": clean, "install.js": "\n"}, {"postinstall": "node install.js"}),
        ],
        # A scriptless hijack: the young version runs its payload when imported.
        "colorlog": [
            ("3.1.0", 90 * DAY, {}, {"index.js": clean, "cli.js": CLI}, {}),
            ("3.1.1", 4 * HOUR, {}, {"index.js": payload("import-payload-ran"), "cli.js": CLI}, {}),
        ],
        # A newer major line that adds a scripted dependency. npm never picks it for "^2".
        # Regression for a false alarm seen with better-sqlite3 -> tar-stream 2.x vs 3.x.
        "tarlike": [
            ("2.2.0", 300 * DAY, {}, {"index.js": clean}, {}),
            ("3.2.2", 36 * HOUR, {"fastbuild": "^0.25.0"}, {"index.js": clean}, {}),
        ],
        "needs-tarlike": [
            ("1.0.0", 200 * DAY, {"tarlike": "^2.2.0"}, {"index.js": clean}, {}),
        ],
        # A legitimate fresh release that adds a long-established dependency with an install script.
        # Regression for the false alarm seen after one week of real use: astro 7.3.6 -> rolldown.
        "nativebind": [
            ("1.4.0", 400 * DAY, {}, {"index.js": clean, "install.js": "\n"}, {"postinstall": "node install.js"}),
        ],
        "sitegen": [
            ("7.3.5", 30 * DAY, {}, {"index.js": clean}, {}),
            ("7.3.6", 1 * HOUR, {"nativebind": "^1.4.0"}, {"index.js": clean}, {}),
        ],
        # Old, boring, no scripts.
        "left-pad-ok": [
            ("1.3.0", 400 * DAY, {}, {"index.js": clean}, {}),
        ],
    }


def tarball(name, version, deps, files, scripts):
    manifest = {"name": name, "version": version, "main": "index.js", "dependencies": deps, "scripts": scripts}
    if "cli.js" in files:
        manifest["bin"] = {name: "cli.js"}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, text in {"package.json": json.dumps(manifest), **files}.items():
            data = text.encode()
            info = tarfile.TarInfo(f"package/{path}")
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build(marker, port, now=None):
    """Return (packuments, tarballs) keyed by name and tarball path."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    base = f"http://127.0.0.1:{port}"
    docs, blobs = {}, {}
    for name, releases in catalogue(marker, port).items():
        versions, times = {}, {}
        for version, age, deps, files, scripts in releases:
            blob = tarball(name, version, deps, files, scripts)
            path = f"/{name}/-/{name}-{version}.tgz"
            blobs[path] = blob
            meta = {"name": name, "version": version, "dependencies": deps, "scripts": scripts,
                    "dist": {"tarball": base + path, "shasum": hashlib.sha1(blob).hexdigest(),
                             "integrity": "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode()}}
            if "cli.js" in files:
                meta["bin"] = {name: "cli.js"}
            if any(k in scripts for k in ("preinstall", "install", "postinstall")):
                meta["hasInstallScript"] = True
            versions[version] = meta
            times[version] = (now - age).isoformat().replace("+00:00", "Z")
        newest = max(releases, key=lambda r: -r[1].total_seconds())
        latest = max((r for r in releases if r[0].startswith("1.") or name != "axios"),
                     key=lambda r: -r[1].total_seconds())
        times["created"] = min(times[v] for v in versions)
        times["modified"] = times[newest[0]]
        docs[name] = {"name": name, "dist-tags": {"latest": latest[0]}, "versions": versions, "time": times}
    return docs, blobs


def serve(marker, port=4873):
    """Start the registry in a background thread. Returns (server, c2_hits)."""
    docs, blobs = build(marker, port)
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            if path.startswith("/c2/"):
                hits.append(path)
                return self.reply(200, b"ok", "text/plain")
            if path in blobs:
                return self.reply(200, blobs[path], "application/octet-stream")
            name = path.strip("/").replace("%2f", "/").replace("%2F", "/")
            if name in docs:
                return self.reply(200, json.dumps(docs[name]).encode(), "application/json")
            self.reply(404, b'{"error":"not found"}', "application/json")

        def reply(self, code, body, kind):
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hits


if __name__ == "__main__":
    marker = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fake-registry-markers")
    marker.mkdir(parents=True, exist_ok=True)
    serve(str(marker))
    print(f"fake registry on http://127.0.0.1:4873, markers in {marker}")
    threading.Event().wait()
