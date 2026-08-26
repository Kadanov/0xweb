from pathlib import Path
import base64
import hashlib
import hmac
import html
import re
import secrets
import sqlite3
import subprocess
import urllib.parse

from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE = Path(__file__).resolve().parent
DATA = BASE.parent / "data"
DB = DATA / "0xweb.db"
UPLOADS = BASE / "static" / "uploads"
FILES = BASE / "static" / "files"

UPLOADS.mkdir(parents=True, exist_ok=True)
FILES.mkdir(parents=True, exist_ok=True)
DATA.mkdir(parents=True, exist_ok=True)

# Per-deployment secret so flag values are NOT guessable from their pattern.
# Persisted in data/ so flags stay stable across restarts (regenerated only if
# the file is deleted). This is what stops anyone submitting all flags without
# actually exploiting each challenge.
def _load_flag_secret():
    p = DATA / "flag_secret.txt"
    try:
        if p.exists():
            v = p.read_text(encoding="utf-8").strip()
            if v:
                return v
        v = secrets.token_hex(16)
        p.write_text(v, encoding="utf-8")
        return v
    except Exception:
        return "0xweb-fallback-secret"


FLAG_SECRET = _load_flag_secret()

app = FastAPI(title="0xweb")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))


# ---------------------------------------------------------------------------
# Catalog metadata (drives the UI). Each category maps to a real endpoint and
# exposes 3 difficulty levels via ?level=. Higher levels add filters/mitigations
# that must be bypassed. The lab reveals the vuln class by name (methodical
# review), but not the bypass technique.
# ---------------------------------------------------------------------------

CATEGORIES = [
    {
        "slug": "traversal",
        "num": 1,
        "name": "Directory Traversal",
        "objective": "Read files outside the intended directory (e.g. app/secret.txt, /etc/passwd).",
        "levels": [
            {"n": 1, "note": "No filtering.", "entry": "/download?file=public.txt&level=1"},
            {"n": 2, "note": "Naive '../' rejection.", "entry": "/download?file=public.txt&level=2"},
            {"n": 3, "note": "Non-recursive strip + absolute-path block.", "entry": "/download?file=public.txt&level=3"},
        ],
    },
    {
        "slug": "lfi",
        "num": 2,
        "name": "Local File Inclusion",
        "objective": "Make the content viewer include an arbitrary local file.",
        "levels": [
            {"n": 1, "note": "Unknown page falls through to disk.", "entry": "/include?page=home&level=1"},
            {"n": 2, "note": "'..' rejected (try absolute paths).", "entry": "/include?page=home&level=2"},
            {"n": 3, "note": "Non-recursive '../' strip.", "entry": "/include?page=home&level=3"},
        ],
    },
    {
        "slug": "sqli-union",
        "num": 3,
        "name": "SQL Injection — UNION-based",
        "objective": "Exfiltrate the row in the `secrets` table via a UNION SELECT.",
        "levels": [
            {"n": 1, "note": "Raw numeric injection.", "entry": "/product?id=1&level=1"},
            {"n": 2, "note": "Lowercase union/select stripped.", "entry": "/product?id=1&level=2"},
            {"n": 3, "note": "Whitespace blocked (use comments).", "entry": "/product?id=1&level=3"},
        ],
    },
    {
        "slug": "sqli-blind",
        "num": 4,
        "name": "SQL Injection — Blind",
        "objective": "Blind-extract the per-level flag from the `blind` table, one character at a time.",
        "levels": [
            {"n": 1, "note": "Boolean-blind (numeric).", "entry": "/api/lookup?id=1&level=1"},
            {"n": 2, "note": "AND/OR keyword filter.", "entry": "/api/lookup?id=1&level=2"},
            {"n": 3, "note": "Time-based only (response never changes).", "entry": "/api/lookup?id=1&level=3"},
        ],
    },
    {
        "slug": "cmdi",
        "num": 5,
        "name": "Command Injection",
        "objective": "Run OS commands to read the per-level flag files (/tmp/flag_cmdi_l*.txt).",
        "levels": [
            {"n": 1, "note": "Raw shell string.", "entry": "/tools/ping?host=127.0.0.1&level=1"},
            {"n": 2, "note": "; and && and | stripped.", "entry": "/tools/ping?host=127.0.0.1&level=2"},
            {"n": 3, "note": "Also $ and ( ) stripped.", "entry": "/tools/ping?host=127.0.0.1&level=3"},
        ],
    },
    {
        "slug": "xss-reflected",
        "num": 6,
        "name": "XSS — Reflected",
        "objective": "Execute JavaScript (pop alert(document.domain)).",
        "levels": [
            {"n": 1, "note": "Raw reflection.", "entry": "/search?q=0xweb&level=1"},
            {"n": 2, "note": "<script> stripped once.", "entry": "/search?q=0xweb&level=2"},
            {"n": 3, "note": "Reflected inside an attribute.", "entry": "/search?q=0xweb&level=3"},
        ],
    },
    {
        "slug": "xss-stored",
        "num": 7,
        "name": "XSS — Stored",
        "objective": "Persist a payload in the comments that executes for every visitor.",
        "levels": [
            {"n": 1, "note": "Rendered with |safe.", "entry": "/comments?level=1"},
            {"n": 2, "note": "<script> stripped on render.", "entry": "/comments?level=2"},
            {"n": 3, "note": "Rendered inside an attribute.", "entry": "/comments?level=3"},
        ],
    },
    {
        "slug": "xss-dom",
        "num": 8,
        "name": "XSS — DOM-based",
        "objective": "Trigger a client-side sink from the URL (no server round-trip).",
        "levels": [
            {"n": 1, "note": "innerHTML sink.", "entry": "/dom?value=0xweb&level=1"},
            {"n": 2, "note": "<script> filtered in JS.", "entry": "/dom?value=0xweb&level=2"},
            {"n": 3, "note": "href / javascript: sink.", "entry": "/dom?value=0xweb&level=3"},
        ],
    },
    {
        "slug": "enum-files",
        "num": 9,
        "name": "File / Directory Enumeration",
        "objective": "Discover unlinked files and directories (robots.txt, backups, .env).",
        "levels": [
            {"n": 1, "note": "Leaked by robots.txt.", "entry": "/robots.txt"},
            {"n": 2, "note": "Common backup/dotfile names.", "entry": "/enum"},
            {"n": 3, "note": "Status-code differentiation (403 vs 404).", "entry": "/enum"},
        ],
    },
    {
        "slug": "upload",
        "num": 10,
        "name": "File Upload",
        "objective": "Upload a file that renders active content (SVG/HTML) from /static/uploads/.",
        "levels": [
            {"n": 1, "note": "No restrictions.", "entry": "/uploads?level=1"},
            {"n": 2, "note": "Case-sensitive extension blacklist.", "entry": "/uploads?level=2"},
            {"n": 3, "note": "Extension + content sniff.", "entry": "/uploads?level=3"},
        ],
    },
    {
        "slug": "param",
        "num": 11,
        "name": "Parameter Enumeration",
        "objective": "Find undocumented parameters that change the response.",
        "levels": [
            {"n": 1, "note": "verbose=1 diagnostics.", "entry": "/debug?level=1"},
            {"n": 2, "note": "A hidden token parameter.", "entry": "/debug?level=2"},
            {"n": 3, "note": "A hidden privilege parameter.", "entry": "/debug?level=3"},
        ],
    },
    {
        "slug": "vhost",
        "num": 12,
        "name": "Virtual Host Enumeration",
        "objective": "Reach internal virtual hosts via the Host header (curl -H 'Host: ...').",
        "levels": [
            {"n": 1, "note": "dev.0xweb.local", "entry": "/vhost"},
            {"n": 2, "note": "admin.0xweb.local", "entry": "/vhost"},
            {"n": 3, "note": "A vhost hinted only in a config file.", "entry": "/vhost"},
        ],
    },
    {
        "slug": "idor",
        "num": 13,
        "name": "IDOR / Broken Access Control",
        "objective": "Access other users' objects (admin profile, others' orders).",
        "levels": [
            {"n": 1, "note": "Sequential user_id.", "entry": "/profile?user_id=1&level=1"},
            {"n": 2, "note": "Sequential order_id (no owner check).", "entry": "/api/orders?order_id=1&level=2"},
            {"n": 3, "note": "Base64-encoded object reference.", "entry": "/api/account?level=3"},
        ],
    },
]

CATEGORY_BY_SLUG = {c["slug"]: c for c in CATEGORIES}


# ---------------------------------------------------------------------------
# Flag registry — powers the scoreboard. EVERY level has its own flag, so the
# scoreboard proves each bypass was cleared, not just level 1.
#   token / flag = FLAG{0xweb_<cat>_l<level>}
# ---------------------------------------------------------------------------

# Short cat key used inside the flag token (kept stable / readable).
_CAT_KEY = {
    "traversal": "traversal",
    "lfi": "lfi",
    "sqli-union": "sqli_union",
    "sqli-blind": "sqli_blind",
    "cmdi": "cmdi",
    "xss-reflected": "xss_reflected",
    "xss-stored": "xss_stored",
    "xss-dom": "xss_dom",
    "enum-files": "enum",
    "upload": "upload",
    "param": "param",
    "vhost": "vhost",
    "idor": "idor",
}


def flag_token(cat, level):
    # Readable prefix (for the scoreboard) + unguessable HMAC signature so the
    # flag can only be obtained by actually extracting it from the app.
    key = _CAT_KEY[cat]
    sig = hmac.new(
        FLAG_SECRET.encode(), f"{key}:{level}".encode(), hashlib.sha256
    ).hexdigest()[:8]
    return f"0xweb_{key}_l{level}_{sig}"


def flag_str(cat, level):
    return "FLAG{" + flag_token(cat, level) + "}"


FLAGS = [
    {
        "cat": c["slug"],
        "level": lv,
        "id": flag_token(c["slug"], lv),
        "flag": flag_str(c["slug"], lv),
    }
    for c in CATEGORIES
    for lv in (1, 2, 3)
]

FLAG_BY_STR = {f["flag"]: f for f in FLAGS}
FLAG_IDS = {f["id"] for f in FLAGS}
TOTAL_FLAGS = len(FLAGS)


def read_solved(request: Request) -> set:
    raw = request.cookies.get("solved", "")
    return {t for t in raw.split(".") if t in FLAG_IDS}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()
    cur.executescript(
        """
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        bio TEXT NOT NULL,
        secret TEXT NOT NULL,
        token TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT NOT NULL,
        body TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        flag TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS blind (
        level INTEGER PRIMARY KEY,
        flag TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        item TEXT NOT NULL,
        total REAL NOT NULL,
        note TEXT NOT NULL
    );
    """
    )

    if cur.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO products(id,name,description,price) VALUES(?,?,?,?)",
            [
                (1, "Red Terminal", "A training product.", 19.90),
                (2, "White Shell", "A training product.", 29.90),
                (3, "Hex Notebook", "A training product.", 9.90),
                (4, "Debug Mug", "A training product.", 14.50),
            ],
        )

    if cur.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        # admin.secret -> IDOR L1 (profile), admin.token -> IDOR L3 (base64 account)
        cur.executemany(
            "INSERT INTO users(id,username,role,bio,secret,token) VALUES(?,?,?,?,?,?)",
            [
                (1, "alice", "user", "Frontend developer", "alice-private", ""),
                (2, "bob", "user", "Backend developer", "bob-private", ""),
                (3, "admin", "admin", "System administrator",
                 flag_str("idor", 1), flag_str("idor", 3)),
            ],
        )

    if cur.execute("SELECT COUNT(*) FROM comments").fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO comments(author,body) VALUES(?,?)",
            ("system", "Welcome to 0xweb."),
        )

    if cur.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 0:
        # UNION target: one row per level. Reaching data at level N forces that
        # level's bypass (mixed-case / inline comments).
        cur.executemany(
            "INSERT INTO secrets(id,name,flag) VALUES(?,?,?)",
            [
                (1, "level1", flag_str("sqli-union", 1)),
                (2, "level2", flag_str("sqli-union", 2)),
                (3, "level3", flag_str("sqli-union", 3)),
            ],
        )

    if cur.execute("SELECT COUNT(*) FROM blind").fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO blind(level,flag) VALUES(?,?)",
            [
                (1, flag_str("sqli-blind", 1)),
                (2, flag_str("sqli-blind", 2)),
                (3, flag_str("sqli-blind", 3)),
            ],
        )

    if cur.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO orders(id,user_id,item,total,note) VALUES(?,?,?,?,?)",
            [
                (1, 1, "Red Terminal", 19.90, "alice order"),
                (2, 2, "White Shell", 29.90, "bob order"),
                (3, 3, "Debug Mug", 14.50, "admin order — " + flag_str("idor", 2)),
            ],
        )

    conn.commit()
    conn.close()

    # ---- Files (rewritten every boot) --------------------------------------
    (FILES / "public.txt").write_text(
        "0xweb public file.\nNothing interesting here.\n", encoding="utf-8"
    )
    (FILES / "notes.txt").write_text(
        "Training note: enumeration is often the first step.\n", encoding="utf-8"
    )

    # 1) Directory Traversal — one flag file per level, each needing that
    #    level's technique to reach from /static/files:
    #      L1: ../../secret.txt              (plain traversal)
    #      L2: /tmp/flag_trav_l2.txt         (absolute path — '../' is rejected)
    #      L3: ....//secret3.txt             (needs the ....// strip bypass)
    (BASE / "secret.txt").write_text(
        "0xweb internal secret\n" + flag_str("traversal", 1) + "\n", encoding="utf-8"
    )
    _safe_write("/tmp/flag_trav_l2.txt", flag_str("traversal", 2) + "\n")
    (BASE / "static" / "secret3.txt").write_text(
        flag_str("traversal", 3) + "\n", encoding="utf-8"
    )

    # 2) LFI — one flag file per level (relative to app/ = BASE):
    #      L1: page=lfi_notes.txt
    #      L2: page=/tmp/flag_lfi_l2.txt     (absolute — '..' is rejected)
    #      L3: page=....//flag_lfi_l3.txt    (one dir up from app/)
    (BASE / "lfi_notes.txt").write_text(
        "0xweb internal note\n" + flag_str("lfi", 1) + "\n", encoding="utf-8"
    )
    _safe_write("/tmp/flag_lfi_l2.txt", flag_str("lfi", 2) + "\n")
    (BASE.parent / "flag_lfi_l3.txt").write_text(
        flag_str("lfi", 3) + "\n", encoding="utf-8"
    )

    # 5) Command Injection — one flag file per level (read via that level's
    #    injection technique). Any RCE can read all three; they mark progress.
    _safe_write("/tmp/flag_cmdi_l1.txt", flag_str("cmdi", 1) + "\n")
    _safe_write("/tmp/flag_cmdi_l2.txt", flag_str("cmdi", 2) + "\n")
    _safe_write("/tmp/flag_cmdi_l3.txt", flag_str("cmdi", 3) + "\n")

    # 9) Directory-enumeration decoys (unlinked from the UI on purpose).
    (FILES / "db.sql.bak").write_text(
        "-- 0xweb backup\n-- " + flag_str("enum-files", 1) + "\n"
        "INSERT INTO users VALUES(3,'admin','admin','...');\n",
        encoding="utf-8",
    )
    (FILES / ".env").write_text(
        "APP_ENV=production\nSECRET_KEY=" + flag_str("enum-files", 2) + "\n",
        encoding="utf-8",
    )
    (FILES / "vhosts.conf").write_text(
        "# internal reverse-proxy map\n"
        "server dev.0xweb.local;\n"
        "server admin.0xweb.local;\n"
        "server backup-2024.0xweb.local;  # legacy, do not expose\n",
        encoding="utf-8",
    )


def _safe_write(path, text):
    try:
        Path(path).write_text(text, encoding="utf-8")
    except Exception:
        pass


init_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def clamp_level(level: str) -> int:
    try:
        n = int(level)
    except (TypeError, ValueError):
        return 1
    return n if n in (1, 2, 3) else 1


# ---------------------------------------------------------------------------
# Home / catalog of categories
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "categories": CATEGORIES}
    )


@app.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})


@app.get("/category/{slug}", response_class=HTMLResponse)
async def category(request: Request, slug: str):
    cat = CATEGORY_BY_SLUG.get(slug)
    if not cat:
        return PlainTextResponse("Category not found", status_code=404)
    return templates.TemplateResponse(
        "category.html", {"request": request, "cat": cat}
    )


# Backwards-compatible numeric route.
@app.get("/challenge/{number}", response_class=HTMLResponse)
async def challenge(request: Request, number: int):
    for c in CATEGORIES:
        if c["num"] == number:
            return RedirectResponse(f"/category/{c['slug']}", status_code=307)
    return PlainTextResponse("Challenge not found", status_code=404)


# ---------------------------------------------------------------------------
# 1. Directory Traversal
# ---------------------------------------------------------------------------

@app.get("/download")
async def download(file: str = "public.txt", level: str = "1"):
    lvl = clamp_level(level)
    raw = file

    if lvl == 2:
        # Naive rejection of the classic dot-dot-slash sequence.
        if "../" in raw or "..\\" in raw:
            return PlainTextResponse("Blocked: path traversal detected", status_code=400)
    elif lvl == 3:
        # Non-recursive strip + block absolute paths.
        if raw.startswith("/"):
            return PlainTextResponse("Blocked: absolute path", status_code=400)
        raw = raw.replace("../", "")

    target = FILES / raw
    try:
        return PlainTextResponse(target.read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        return PlainTextResponse("File not found", status_code=404)
    except IsADirectoryError:
        return PlainTextResponse("Not a file", status_code=400)
    except Exception as exc:
        return PlainTextResponse(f"Error: {exc}", status_code=400)


# ---------------------------------------------------------------------------
# 2. Local File Inclusion
# ---------------------------------------------------------------------------

@app.get("/include", response_class=HTMLResponse)
async def include(request: Request, page: str = "home", level: str = "1"):
    lvl = clamp_level(level)
    candidates = {
        "home": BASE / "templates" / "included_home.html",
        "about": BASE / "templates" / "included_about.html",
    }

    if page in candidates:
        content = candidates[page].read_text(encoding="utf-8")
    else:
        raw = page
        if lvl == 2:
            if ".." in raw:
                return HTMLResponse("<h1>Include Viewer</h1><p>Blocked: '..' not allowed.</p>")
        elif lvl == 3:
            raw = raw.replace("../", "")
        target = (Path(raw) if raw.startswith("/") else BASE / raw)
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            content = f"Include error: {html.escape(str(exc))}"

    return HTMLResponse(
        f"""<!doctype html><html><body>
<h1>Include Viewer</h1>
<div>{content}</div>
<p><a href="/category/lfi">Back</a></p>
</body></html>"""
    )


# ---------------------------------------------------------------------------
# 3. SQL Injection — UNION-based
# ---------------------------------------------------------------------------

@app.get("/catalog", response_class=HTMLResponse)
async def catalog(request: Request, q: str = ""):
    conn = db()
    rows = conn.execute("SELECT id,name,description,price FROM products").fetchall()
    conn.close()
    return templates.TemplateResponse(
        "catalog.html", {"request": request, "rows": rows, "q": q}
    )


@app.get("/product", response_class=HTMLResponse)
async def product(request: Request, id: str = "1", level: str = "1"):
    lvl = clamp_level(level)
    payload = id

    if lvl == 2:
        # Lowercase-only keyword strip (bypass: mixed case / nesting).
        payload = payload.replace("union", "").replace("select", "")
    elif lvl == 3:
        # Same strip plus whitespace ban (bypass: /**/ inline comments).
        if " " in payload or "\t" in payload:
            return PlainTextResponse("Blocked: whitespace not allowed", status_code=400)
        payload = payload.replace("union", "").replace("select", "")

    conn = db()
    try:
        rows = conn.execute(
            f"SELECT id,name,description,price FROM products WHERE id = {payload}"
        ).fetchall()
    except sqlite3.Error as exc:
        return PlainTextResponse(f"Database error: {exc}", status_code=500)
    finally:
        conn.close()

    return templates.TemplateResponse(
        "product.html", {"request": request, "rows": rows, "id": id, "level": lvl}
    )


# ---------------------------------------------------------------------------
# 4. SQL Injection — Blind
# ---------------------------------------------------------------------------

@app.get("/api/lookup")
async def api_lookup(id: str = "1", level: str = "1"):
    lvl = clamp_level(level)
    payload = id

    if lvl >= 2:
        # Keyword filter (bypass: mixed case AnD / Or, or /**/).
        payload = re.sub(r"\band\b", "", payload, flags=0)
        payload = re.sub(r"\bor\b", "", payload, flags=0)

    conn = db()
    try:
        row = conn.execute(
            f"SELECT id FROM users WHERE id = {payload}"
        ).fetchone()
    except sqlite3.Error:
        # Blind: never leak the error text.
        row = None
    finally:
        conn.close()

    if lvl == 3:
        # Time-based only: the response is identical no matter what.
        return JSONResponse({"status": "ok"})
    return JSONResponse({"exists": bool(row)})


# ---------------------------------------------------------------------------
# 5. Command Injection
# ---------------------------------------------------------------------------

@app.get("/tools/ping", response_class=PlainTextResponse)
async def ping(host: str = "127.0.0.1", level: str = "1"):
    lvl = clamp_level(level)
    arg = host

    if lvl == 2:
        for bad in (";", "&&", "&", "|"):
            arg = arg.replace(bad, "")
    elif lvl == 3:
        for bad in (";", "&&", "&", "|", "$", "(", ")"):
            arg = arg.replace(bad, "")

    proc = subprocess.run(
        f"ping -c 1 {arg}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=6,
    )
    return proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# 6. XSS — Reflected
# ---------------------------------------------------------------------------

@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, q: str = "", level: str = "1"):
    lvl = clamp_level(level)

    if lvl == 1:
        body = f"<p>Results for: {q}</p>"
    elif lvl == 2:
        # Strip <script> once, case-insensitive (bypass: nested / event handlers).
        cleaned = re.sub(r"<script>", "", q, flags=re.IGNORECASE)
        body = f"<p>Results for: {cleaned}</p>"
    else:
        # Reflected inside an attribute (bypass: break out of the value).
        body = f'<input type="text" value="{q}"><p>Search again.</p>'

    resp = HTMLResponse(
        f"""<!doctype html>
<html><head><title>Search</title></head>
<body>
<h1>Search</h1>
{body}
<p><a href="/category/xss-reflected">Back</a></p>
</body></html>"""
    )
    # Stealable flag cookie — objective is to exfiltrate it via XSS.
    resp.set_cookie("flag_reflected", flag_str("xss-reflected", lvl), httponly=False)
    return resp


# ---------------------------------------------------------------------------
# 7. XSS — Stored
# ---------------------------------------------------------------------------

@app.get("/comments", response_class=HTMLResponse)
async def comments(request: Request, level: str = "1"):
    lvl = clamp_level(level)
    conn = db()
    rows = conn.execute("SELECT id,author,body FROM comments ORDER BY id").fetchall()
    conn.close()
    resp = templates.TemplateResponse(
        "comments.html", {"request": request, "rows": rows, "level": lvl}
    )
    resp.set_cookie("flag_stored", flag_str("xss-stored", lvl), httponly=False)
    return resp


@app.post("/comments")
async def add_comment(author: str = Form(...), body: str = Form(...), level: str = Form("1")):
    lvl = clamp_level(level)
    conn = db()
    conn.execute("INSERT INTO comments(author,body) VALUES(?,?)", (author, body))
    conn.commit()
    conn.close()
    return RedirectResponse(f"/comments?level={lvl}", status_code=303)


# ---------------------------------------------------------------------------
# 8. XSS — DOM-based
# ---------------------------------------------------------------------------

@app.get("/dom", response_class=HTMLResponse)
async def dom(request: Request, level: str = "1"):
    lvl = clamp_level(level)
    resp = templates.TemplateResponse("dom.html", {"request": request, "level": lvl})
    resp.set_cookie("flag_dom", flag_str("xss-dom", lvl), httponly=False)
    return resp


# ---------------------------------------------------------------------------
# 9. File / Directory Enumeration
# ---------------------------------------------------------------------------

@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return (
        "User-agent: *\n"
        "Disallow: /static/files/db.sql.bak\n"
        "Disallow: /admin-panel\n"
        "Disallow: /server-status\n"
    )


@app.get("/enum", response_class=HTMLResponse)
async def enum_hint(request: Request):
    return templates.TemplateResponse("enumeration.html", {"request": request})


@app.get("/admin-panel", response_class=PlainTextResponse)
async def admin_panel(token: str = ""):
    # Exists but forbidden — 403 (distinct from a 404) is the enumeration signal.
    if token == "0xweb-internal":
        return PlainTextResponse("admin panel\n" + flag_str("enum-files", 3) + "\n")
    return PlainTextResponse("403 Forbidden", status_code=403)


@app.get("/server-status", response_class=PlainTextResponse)
async def server_status():
    return PlainTextResponse("Server status: OK\n" + flag_str("enum-files", 3) + "\n")


# ---------------------------------------------------------------------------
# 10. File Upload
# ---------------------------------------------------------------------------

DANGEROUS_EXTS = {".html", ".htm", ".svg", ".xhtml", ".xml", ".js"}


@app.post("/upload")
async def upload(file: UploadFile = File(...), level: str = Form("1")):
    lvl = clamp_level(level)
    name = Path(file.filename or "upload.bin").name
    data = await file.read()
    suffix = Path(name).suffix

    if lvl == 2:
        # Case-sensitive blacklist (bypass: .SVG / .HtmL).
        if suffix in DANGEROUS_EXTS:
            return PlainTextResponse(
                "Blocked: file type not allowed", status_code=400
            )
    elif lvl == 3:
        # Content sniff of only the first 512 bytes (bypass: pad the front with a
        # long comment so the <svg>/<script> markup falls past the sniff window).
        head = data[:512].lower()
        if b"<script" in head or b"<svg" in head or b"<html" in head:
            return PlainTextResponse("Blocked: active content detected", status_code=400)

    destination = UPLOADS / f"{secrets.token_hex(4)}_{name}"
    destination.write_bytes(data)

    servable = destination.suffix.lower() in DANGEROUS_EXTS or b"<script" in data[:2048].lower()
    # Per-level flag: awarded only if this level's specific check was bypassed.
    flag = flag_str("upload", lvl) if servable else ""
    return RedirectResponse(
        url=f"/uploads?name={urllib.parse.quote(destination.name)}&level={lvl}"
        + (f"&flag={flag}" if flag else ""),
        status_code=303,
    )


@app.get("/uploads", response_class=HTMLResponse)
async def uploads(request: Request, name: str = "", level: str = "1", flag: str = ""):
    lvl = clamp_level(level)
    files = sorted(p.name for p in UPLOADS.iterdir() if p.is_file() and p.name != ".gitkeep")
    return templates.TemplateResponse(
        "uploads.html",
        {"request": request, "files": files, "name": name, "level": lvl, "flag": flag},
    )


# ---------------------------------------------------------------------------
# 11. Parameter Enumeration
# ---------------------------------------------------------------------------

@app.get("/debug")
async def debug(
    request: Request,
    level: str = "1",
    verbose: str = "",
    format: str = "",
    preview: str = "",
    debug_token: str = "",
    admin: str = "",
):
    lvl = clamp_level(level)

    if lvl == 1:
        # Undocumented verbose flag reveals the flag.
        if verbose == "1":
            return JSONResponse(
                {
                    "debug": True,
                    "build": "0xweb-dev",
                    "flag": flag_str("param", 1),
                    "note": "There are more parameters you may not see in the UI.",
                }
            )
        if format == "json":
            return JSONResponse({"status": "ok", "mode": "json"})
        if preview == "1":
            return JSONResponse({"preview": True, "message": "Preview mode is enabled."})
        return JSONResponse({"status": "ok"})

    if lvl == 2:
        # Hidden token parameter (find it with a parameter wordlist).
        if debug_token == "0xweb":
            return JSONResponse({"debug_token": "accepted", "flag": flag_str("param", 2)})
        return JSONResponse({"status": "ok"})

    # lvl 3: hidden privilege parameter.
    if admin == "true":
        return JSONResponse({"admin": True, "flag": flag_str("param", 3)})
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# 12. Virtual Host Enumeration (Host header routing)
# ---------------------------------------------------------------------------

VHOSTS = {
    "dev.0xweb.local": "dev environment\n" + flag_str("vhost", 1) + "\n",
    "admin.0xweb.local": "admin console\n" + flag_str("vhost", 2) + "\n",
    "backup-2024.0xweb.local": "legacy backup host\n" + flag_str("vhost", 3) + "\n",
}


@app.get("/vhost", response_class=HTMLResponse)
async def vhost_hint(request: Request):
    return templates.TemplateResponse("vhost.html", {"request": request})


@app.middleware("http")
async def vhost_router(request: Request, call_next):
    host = request.headers.get("host", "").split(":")[0].lower()
    if host in VHOSTS:
        return PlainTextResponse(VHOSTS[host])
    return await call_next(request)


# ---------------------------------------------------------------------------
# 13. IDOR / Broken Access Control
# ---------------------------------------------------------------------------

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, user_id: str = "1", level: str = "1"):
    conn = db()
    try:
        row = conn.execute(
            f"SELECT id,username,role,bio,secret FROM users WHERE id = {user_id}"
        ).fetchone()
    except sqlite3.Error as exc:
        return PlainTextResponse(f"Database error: {exc}", status_code=500)
    finally:
        conn.close()

    if not row:
        return PlainTextResponse("User not found", status_code=404)
    return templates.TemplateResponse("profile.html", {"request": request, "row": row})


@app.get("/api/profile")
async def api_profile(user_id: str = "1", fields: str = ""):
    conn = db()
    try:
        row = conn.execute(
            f"SELECT id,username,role,bio,secret FROM users WHERE id = {user_id}"
        ).fetchone()
    except sqlite3.Error as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
    finally:
        conn.close()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)

    data = dict(row)
    if fields:
        wanted = [x.strip() for x in fields.split(",")]
        data = {k: v for k, v in data.items() if k in wanted}
    return JSONResponse(data)


@app.get("/api/orders")
async def api_orders(order_id: str = "1", level: str = "2"):
    # No ownership check — any order_id is returned (IDOR level 2).
    conn = db()
    try:
        row = conn.execute(
            "SELECT id,user_id,item,total,note FROM orders WHERE id = ?",
            (order_id,),
        ).fetchone()
    except sqlite3.Error as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
    finally:
        conn.close()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(dict(row))


@app.get("/api/account")
async def api_account(ref: str = "", level: str = "3"):
    # Object reference is base64(user_id). Decode, change it, re-encode (IDOR level 3).
    if not ref:
        # Hand out the current user's reference so the pattern is discoverable.
        return JSONResponse(
            {
                "hint": "pass ?ref=<base64 of a user id>",
                "example_ref": base64.b64encode(b"1").decode(),
            }
        )
    try:
        uid = base64.b64decode(ref).decode().strip()
    except Exception:
        return JSONResponse({"error": "bad ref"}, status_code=400)

    conn = db()
    try:
        row = conn.execute(
            "SELECT id,username,role,secret,token FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(dict(row))


# ---------------------------------------------------------------------------
# Scoreboard / flag submission
# ---------------------------------------------------------------------------

def build_board(solved: set):
    """Group flags by category with solved state, for the scoreboard template."""
    board = []
    for c in CATEGORIES:
        flags = sorted(
            [
                {**f, "solved": f["id"] in solved, "label": f"Level {f['level']}"}
                for f in FLAGS
                if f["cat"] == c["slug"]
            ],
            key=lambda f: f["level"],
        )
        if not flags:
            continue
        board.append(
            {
                "slug": c["slug"],
                "num": c["num"],
                "name": c["name"],
                "flags": flags,
                "done": sum(1 for f in flags if f["solved"]),
                "total": len(flags),
            }
        )
    return board


@app.get("/submit", response_class=HTMLResponse)
async def submit_get(request: Request, status: str = ""):
    solved = read_solved(request)
    board = build_board(solved)
    return templates.TemplateResponse(
        "submit.html",
        {
            "request": request,
            "board": board,
            "solved_count": len(solved),
            "total": TOTAL_FLAGS,
            "status": status,
        },
    )


@app.post("/submit")
async def submit_post(request: Request, flag: str = Form(...)):
    solved = read_solved(request)
    candidate = flag.strip()
    match = FLAG_BY_STR.get(candidate)

    if match:
        already = match["id"] in solved
        solved.add(match["id"])
        status = "dup" if already else "ok"
    else:
        status = "bad"

    resp = RedirectResponse(f"/submit?status={status}", status_code=303)
    resp.set_cookie("solved", ".".join(sorted(solved)), max_age=60 * 60 * 24 * 30)
    return resp


@app.get("/reset-progress")
async def reset_progress():
    resp = RedirectResponse("/submit?status=reset", status_code=303)
    resp.delete_cookie("solved")
    return resp
