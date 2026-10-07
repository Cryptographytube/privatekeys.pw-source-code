#!/usr/bin/env python3
"""
OPTIONAL Passenger / WSGI entry point for cPanel's "Setup Python App".

You do NOT need this to put the site online. The .htaccess already serves the
whole static mirror on any Apache/cPanel host. Enable this ONLY if you also want
the LIVE key-directory engine working on the server:

    /keys/<coin>/<page>            browse any directory page
    /keys/<coin>/<page>/export     CSV of that page
    /keys/<coin>/random            a random page
    /key/<hex>                     details for any private key

Everything else (home, puzzles + filters + export, calculator, FAQ, brainwallet,
richest, individual puzzles, images, assets) is still served from the mirrored
files, exactly like the static version.

How to turn it on in cPanel (no pip packages needed — standard library only):
  1. cPanel  ->  "Setup Python App"  ->  Create Application
  2. Python version: 3.8+   |   Application root: the folder these files live in
     Application URL: your domain (root "/")   |   Startup file: passenger_wsgi.py
     Application Entry point: application
  3. Create, then click "Restart".
If your host has no "Setup Python App", just ignore this file.
"""
import os, re, sys
from urllib.parse import unquote, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import keygen  # the on-demand crypto/HTML engine (pure standard library)
except Exception as _e:  # pragma: no cover
    keygen = None
    sys.stderr.write("keygen engine unavailable, serving static only: %s\n" % _e)

ROOT = os.path.dirname(os.path.abspath(__file__))

MIME = {
    ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8", ".svg": "image/svg+xml",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".ico": "image/x-icon", ".webp": "image/webp", ".woff": "font/woff", ".woff2": "font/woff2",
    ".ttf": "font/ttf", ".txt": "text/plain; charset=utf-8", ".xml": "application/xml; charset=utf-8",
    ".map": "application/json; charset=utf-8", ".csv": "text/csv; charset=utf-8",
}
# Never hand these out as files.
BLOCKED_TOP = {"passenger_wsgi.py", "keygen.py", ".htaccess", "_tools", "__pycache__"}

RE_KEYS = re.compile(r"^/keys/([a-z0-9-]+)/(\d+)(/export)?/?$")
RE_KEYS_RANDOM = re.compile(r"^/keys/([a-z0-9-]+)/random/?$")
RE_KEYS_PUZZLE = re.compile(r"^/keys/([a-z0-9-]+)/puzzle-(\d+)(?:/random)?/?$")
RE_KEY = re.compile(r"^/key/([0-9a-fA-F]{1,64})/?$")


def _puzzle_page(n):
    """The numeric directory page that holds puzzle #n's first key (2^(n-1))."""
    if n < 1:
        return None
    start = 1 << (n - 1)                       # 2^(n-1)
    if start >= keygen.N:                       # past the secp256k1 order
        return None
    page = (start - 1) // keygen.PER_PAGE + 1
    if page < 1 or page > keygen.TOTAL_PAGES:
        return None
    return page


def content_type(path):
    return MIME.get(os.path.splitext(path)[1].lower(), "text/html; charset=utf-8")


def safe_join(rel):
    import posixpath
    rel = rel.replace("\\", "/").lstrip("/")
    full = posixpath.normpath(os.path.join(ROOT, rel).replace("\\", "/"))
    root_norm = posixpath.normpath(ROOT.replace("\\", "/"))
    if not (full == root_norm or full.startswith(root_norm + "/")):
        return None
    top = rel.split("/", 1)[0]
    if top in BLOCKED_TOP or top.startswith("."):
        return None
    return full


def resolve(path, query):
    rel = unquote(path).lstrip("/")
    if rel in ("", "/"):
        rel = "index.html"
    if rel.startswith("build/assets/"):
        rel = "assets/" + rel[len("build/assets/"):]
    candidates = []
    if query:
        candidates.append(rel + query)       # /puzzles?page=2 -> puzzlespage=2
    candidates.append(rel)                    # exact
    candidates.append(rel + ".html")          # /keys/bitcoin/1 -> keys/bitcoin/1.html
    base = rel.rsplit("/", 1)[-1]
    candidates.append(rel + "/" + base)       # /mnemonic/bitcoin -> mnemonic/bitcoin/bitcoin
    candidates.append(rel + "/index.html")
    candidates.append(rel + "/index")
    for c in candidates:
        full = safe_join(c)
        if full and os.path.isfile(full):
            return full
    return None


def _load_404():
    try:
        with open(os.path.join(ROOT, "404.html"), "rb") as f:
            return f.read()
    except OSError:
        return b"<!doctype html><title>Not found</title><h1>Page not found</h1>"


FALLBACK_404 = _load_404()


def _engine(path, query):
    """Return (status, body_bytes, ctype, extra_headers) for an engine route, or None."""
    if keygen is None:
        return None
    q = parse_qs(query)

    m = RE_KEYS.match(path)
    if m:
        coin, page_s, export = m.group(1), m.group(2), m.group(3)
        if coin not in keygen.COINS:
            return None
        if q.get("jump", ["0"])[0] == "1" and q.get("page"):
            try:
                page = int(q["page"][0])
            except ValueError:
                page = int(page_s)
        else:
            page = int(page_s)
        if export:
            body = keygen.render_csv(coin, page)
            if body is None:
                return None
            if isinstance(body, str):
                body = body.encode("utf-8")
            return ("200 OK", body, "text/csv; charset=utf-8",
                    [("Content-Disposition", 'attachment; filename="%s-page-%d.csv"' % (coin, page))])
        doc = keygen.render_directory(coin, page, q.get("type", ["legacy"])[0])
        if doc is None:
            return None
        return ("200 OK", doc.encode("utf-8"), "text/html; charset=utf-8", [])

    m = RE_KEYS_RANDOM.match(path)
    if m:
        coin = m.group(1)
        if coin not in keygen.COINS:
            return None
        import secrets
        page = secrets.randbelow(keygen.TOTAL_PAGES) + 1
        doc = keygen.render_directory(coin, page, q.get("type", ["legacy"])[0])
        return ("200 OK", doc.encode("utf-8"), "text/html; charset=utf-8", [])

    m = RE_KEYS_PUZZLE.match(path)
    if m:
        coin = m.group(1)
        if coin not in keygen.COINS:
            return None
        page = _puzzle_page(int(m.group(2)))
        if page is None:
            return None
        doc = keygen.render_directory(coin, page, q.get("type", ["legacy"])[0])
        return ("200 OK", doc.encode("utf-8"), "text/html; charset=utf-8", [])

    m = RE_KEY.match(path)
    if m:
        doc = keygen.render_key_detail(m.group(1))
        if doc is None:
            return None
        return ("200 OK", doc.encode("utf-8"), "text/html; charset=utf-8", [])

    return None


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/") or "/"
    query = environ.get("QUERY_STRING", "")
    head_only = environ.get("REQUEST_METHOD", "GET") == "HEAD"

    def respond(status, body, ctype, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        headers = [("Content-Type", ctype), ("Content-Length", str(len(body))),
                   ("Cache-Control", "no-cache")]
        if extra:
            headers += extra
        start_response(status, headers)
        return [b"" if head_only else body]

    # Quietly satisfy the live-scanner probes the mirror's JS makes.
    if path == "/json" or path.startswith("/api/"):
        return respond("200 OK", b"[]", "application/json; charset=utf-8")

    # Bitcoin-puzzle CSV export (parent is a file, so it can't be a static path).
    if path.rstrip("/") == "/puzzles/bitcoin-puzzle-tx/export":
        status = parse_qs(query).get("status", ["unsolved"])[0]
        if status not in ("unsolved", "solved", "all"):
            status = "unsolved"
        csv_path = os.path.join(ROOT, "puzzles", "_exports", "bitcoin-puzzle-tx-%s.csv" % status)
        try:
            with open(csv_path, "rb") as f:
                body = f.read()
        except OSError:
            return respond("404 Not Found", FALLBACK_404, "text/html; charset=utf-8")
        return respond("200 OK", body, "text/csv; charset=utf-8",
                       [("Content-Disposition", 'attachment; filename="bitcoin-puzzle-tx-%s.csv"' % status)])

    # Live key-directory engine (overrides the static page-1 snapshots).
    hit = _engine(path, query)
    if hit is not None:
        return respond(*hit)

    full = resolve(path, query)
    if full is None:
        return respond("404 Not Found", FALLBACK_404, "text/html; charset=utf-8")
    try:
        with open(full, "rb") as f:
            body = f.read()
    except OSError:
        return respond("404 Not Found", FALLBACK_404, "text/html; charset=utf-8")
    return respond("200 OK", body, content_type(full))


# Allow running directly for a quick local check:  python passenger_wsgi.py 8099
if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print("WSGI test server on http://127.0.0.1:%d/ (Ctrl+C to stop)" % port)
    make_server("127.0.0.1", port, application).serve_forever()
