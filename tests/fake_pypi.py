"""A tiny local Python package index that replays an Axios-style attack with a harmless payload.

requestz 2.31.1 (2 hours old) adds cryptohelperz, a brand-new source-only package whose
build backend runs code during `pip install`. colorlogz 3.1.1 runs its payload on import.
Payloads only write marker files and call this server's /c2 path.
Serves the PEP 691 JSON simple API with PEP 700 upload times, plus the /pypi/<name>/json API.
"""
import base64
import datetime
import hashlib
import io
import json
import tarfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOUR = datetime.timedelta(hours=1)
DAY = datetime.timedelta(days=1)

PAYLOAD = '''import os, urllib.request
open(os.path.join({marker!r}, {what!r}), "w").write("ran")
try:
    urllib.request.urlopen("http://127.0.0.1:{port}/c2/{what}", timeout=2)
except Exception:
    pass
'''


def catalogue(marker, port):
    def payload(what):
        return PAYLOAD.format(marker=marker, port=port, what=what)

    clean = "\n"
    # name -> list of (version, age, requires, kind, module code)
    return {
        "requestz": [
            ("2.31.0", 40 * DAY, [], "wheel", clean),
            ("2.31.1", 2 * HOUR, ["cryptohelperz>=1.0"], "wheel", clean),
        ],
        "cryptohelperz": [
            ("1.0.0", 3 * HOUR, [], "sdist", payload("build-payload-ran")),
        ],
        "sitetoolz": [
            ("1.0.0", 90 * DAY, ["requestz>=2.31"], "wheel", "import requestz\n"),
        ],
        "colorlogz": [
            ("3.1.0", 90 * DAY, [], "wheel", clean),
            ("3.1.1", 4 * HOUR, [], "wheel", payload("import-payload-ran")),
        ],
        "oldsdistz": [
            ("0.9.0", 500 * DAY, [], "sdist", clean),
        ],
    }


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wheel(name, version, requires, code):
    files = {f"{name}/__init__.py": code.encode()}
    dist = f"{name}-{version}.dist-info"
    meta = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n" + "".join(f"Requires-Dist: {r}\n" for r in requires)
    files[f"{dist}/METADATA"] = meta.encode()
    files[f"{dist}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: fake\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = "".join(f"{p},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()},{len(d)}\n"
                     for p, d in files.items()) + f"{dist}/RECORD,,\n"
    files[f"{dist}/RECORD"] = record.encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p, d in files.items():
            z.writestr(zipfile.ZipInfo(p, (1980, 1, 1, 0, 0, 0)), d)
    return f"{name}-{version}-py3-none-any.whl", buf.getvalue()


BACKEND = '''# An in-tree build backend. Its import is where a malicious sdist runs code.
{code}
import os, zipfile, base64, hashlib
NAME, VERSION = {name!r}, {version!r}

def get_requires_for_build_wheel(config_settings=None):
    return []

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    dist = f"{{NAME}}-{{VERSION}}.dist-info"
    files = {{f"{{NAME}}/__init__.py": b"\\n",
             f"{{dist}}/METADATA": f"Metadata-Version: 2.1\\nName: {{NAME}}\\nVersion: {{VERSION}}\\n".encode(),
             f"{{dist}}/WHEEL": b"Wheel-Version: 1.0\\nGenerator: fake\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"}}
    rec = "".join(f"{{p}},sha256={{base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()}},{{len(d)}}\\n" for p, d in files.items())
    files[f"{{dist}}/RECORD"] = (rec + f"{{dist}}/RECORD,,\\n").encode()
    fn = f"{{NAME}}-{{VERSION}}-py3-none-any.whl"
    with zipfile.ZipFile(os.path.join(wheel_directory, fn), "w") as z:
        for p, d in files.items():
            z.writestr(p, d)
    return fn
'''


def sdist(name, version, code):
    root = f"{name}-{version}"
    files = {
        f"{root}/PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        f"{root}/pyproject.toml": '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n',
        f"{root}/backend.py": BACKEND.format(code=code, name=name, version=version),
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(p)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            tar.addfile(info, io.BytesIO(data))
    return f"{name}-{version}.tar.gz", buf.getvalue()


def build(marker, port, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    base = f"http://127.0.0.1:{port}"
    simple, legacy, blobs = {}, {}, {}
    for name, releases in catalogue(marker, port).items():
        files, rel = [], {}
        for version, age, requires, kind, code in releases:
            fn, data = wheel(name, version, requires, code) if kind == "wheel" else sdist(name, version, code)
            blobs[f"/files/{fn}"] = data
            t = (now - age).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            files.append({"filename": fn, "url": f"{base}/files/{fn}", "hashes": {"sha256": sha(data)}, "upload-time": t})
            rel[version] = [{"filename": fn, "upload_time_iso_8601": t, "packagetype": "bdist_wheel" if kind == "wheel" else "sdist",
                             "url": f"{base}/files/{fn}"}]
        simple[name] = {"meta": {"api-version": "1.1"}, "name": name, "files": files, "versions": [r[0] for r in releases]}
        newest = min(releases, key=lambda r: r[1])[0]
        legacy[name] = {"info": {"name": name, "version": newest}, "releases": rel}
    return simple, legacy, blobs


def serve(marker, port):
    simple, legacy, blobs = build(marker, port)
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            parts = [p for p in path.split("/") if p]
            if path.startswith("/c2/"):
                hits.append(path)
                return self.reply(200, b"ok", "text/plain")
            if path in blobs:
                return self.reply(200, blobs[path], "application/octet-stream")
            if len(parts) == 2 and parts[0] == "simple" and parts[1] in simple:
                return self.reply(200, json.dumps(simple[parts[1]]).encode(), "application/vnd.pypi.simple.v1+json")
            if len(parts) == 3 and parts[0] == "pypi" and parts[2] == "json" and parts[1] in legacy:
                return self.reply(200, json.dumps(legacy[parts[1]]).encode(), "application/json")
            self.reply(404, b"not found", "text/plain")

        def do_HEAD(self):
            self.head_only = True
            self.do_GET()

        def reply(self, code, body, kind):
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not getattr(self, "head_only", False):
                self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hits
