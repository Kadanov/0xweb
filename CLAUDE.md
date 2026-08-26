# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

0xweb is a **deliberately vulnerable** FastAPI training lab for web application penetration testing. Every unsafe pattern in `app/main.py` (string-interpolated SQL, `shell=True`, unsanitized path joins, `|safe` in templates, Host-header trust, unrestricted upload) is intentional. Do not "fix" these as security bugs — they are the product. Only treat something as a defect if it breaks a challenge or the app itself.

The lab is localhost-only by design: `docker-compose.yml` binds `127.0.0.1:8000` and must stay that way.

## Commands

```bash
mkdir -p data                 # required before first build: Dockerfile does `COPY data ./data`
docker compose up --build     # http://127.0.0.1:8000
docker compose down
docker compose logs -f        # live logs
```

Run without Docker (native): `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/uvicorn app.main:app --reload --port 8000`. Note: native runs on a Windows drive (`/mnt/c`) cannot traverse to real OS files like `/etc/passwd` (WSL drvfs does not resolve `..` past the mount); traversal to OS files only works inside Docker. `iputils-ping` is installed in the image, so `/tools/ping` runs a real `ping` — native runs may lack it.

Reset DB (also needed after any schema change in `init_db`): `docker compose down && rm -f data/0xweb.db && docker compose up --build`.

There is no test suite, linter, or CI.

## Architecture

Single module `app/main.py` holds every route; `app/templates/` holds Jinja2 pages extending `base.html`; `app/static/` holds CSS, the logo, and runtime-written `files/` and `uploads/` dirs.

**Difficulty levels.** Almost every vulnerable endpoint takes `?level=1|2|3` (`clamp_level()` normalizes it). Level 1 is unfiltered; levels 2–3 add escalating, *intentionally bypassable* filters inline in the handler. When editing a handler, preserve the bypass for each level — the filters are the challenge, not real hardening. Known intended bypasses: traversal L2=absolute path / L3=`....//`; LFI L2=absolute path / L3=`....//`; SQLi-UNION L2=mixed-case `UnIoN` / L3=`/**/` comments; blind L2=`AnD` / L3=timing via `hex(randomblob(...))`; cmdi L2=`$()` or newline / L3=newline; reflected-XSS L2=event handler / L3=attribute breakout; upload L2=`.SVG` case / L3=pad markup past the 512-byte sniff window.

**Catalog is data-driven.** The `CATEGORIES` list (top of `main.py`) is the single source of truth for the UI: `index.html` renders the grid from it and `category.html` renders one category's three level entry-points. Adding/renaming a challenge means editing `CATEGORIES` plus the handler — templates need no change. `/challenge/{n}` 307-redirects to `/category/{slug}` for backwards compatibility.

**State and setup.** `init_db()` runs at import time (not a startup event). It creates/seeds `data/0xweb.db` (idempotent) and *rewrites on every boot* the flag/decoy files under `app/static/files/` (`db.sql.bak`, `.env`, `vhosts.conf`, plus `public.txt`/`notes.txt`), `app/lfi_notes.txt`, `app/secret.txt`, and `/tmp/flag_cmdi.txt`. Flags live in source/DB, not derived — resetting the DB does not touch the on-disk flag files. `data/` and `app/static/uploads/` are bind-mounted volumes.

**Two escaping regimes.** Routes returning `TemplateResponse` get Jinja autoescaping (safe unless a template opts out with `|safe` — see `comments.html`), while `/search` and `/include` build f-string `HTMLResponse` with no escaping. Keep that split: moving `/search` to a template would kill the reflected-XSS challenge.

**Virtual-host routing.** An `@app.middleware("http")` inspects the `Host` header and short-circuits to a per-vhost flag page for hosts in `VHOSTS` before normal routing; any other Host falls through to the real app. Test with `curl -H "Host: admin.0xweb.local"`. The L3 vhost name is intentionally only discoverable by reading `app/static/files/vhosts.conf` via another challenge (traversal/enumeration) — a cross-challenge dependency.

**Scoreboard & per-level flags.** Every (category, level) pair has its own flag `FLAG{0xweb_<catkey>_l<level>_<hmac8>}` — 39 total. The 8-hex suffix is `HMAC-SHA256(FLAG_SECRET, "cat:level")`; `FLAG_SECRET` is a per-deployment random token persisted in `data/flag_secret.txt`, so flags can't be guessed from the pattern and submitting the readable prefix alone is rejected. `FLAGS` is generated from `CATEGORIES` × levels 1–3 (see `flag_str()`/`_CAT_KEY`); it is the single source of truth for `/submit`. Endpoints embed the level flag via `flag_str(cat, lvl)` — never hard-code a flag string. Per-level sources: traversal/LFI/cmdi use one file per level (distinct target paths, some reached only by that level's bypass); SQLi-UNION uses 3 rows in `secrets`, SQLi-blind 3 rows in `blind`; XSS sets a per-level non-HttpOnly cookie (`flag_reflected/stored/dom`) stolen via `document.cookie`; upload/param/vhost/enum/idor return the level flag directly. `POST /submit` validates against `FLAG_BY_STR`, stores solved ids in a dot-joined `solved` cookie (per-browser, 30-day); `/reset-progress` clears it. Changing the DB schema (users.token, `blind`, 3 `secrets` rows) requires deleting `data/0xweb.db`.

## Category → endpoint map

| # | Category | Endpoint(s) |
|---|---|---|
| 1 | Directory Traversal | `/download?file=&level=` |
| 2 | LFI | `/include?page=&level=` |
| 3 | SQLi UNION | `/product?id=&level=` (target: `secrets` table) |
| 4 | SQLi Blind | `/api/lookup?id=&level=` (target: `users.secret` for admin) |
| 5 | Command Injection | `/tools/ping?host=&level=` |
| 6 | XSS Reflected | `/search?q=&level=` |
| 7 | XSS Stored | `/comments` (GET render + POST), `level` on both |
| 8 | XSS DOM | `/dom?value=&level=` (sink chosen client-side in `dom.html`) |
| 9 | File/Dir Enumeration | `/robots.txt`, `/static/files/*`, `/admin-panel` (403), `/server-status` |
| 10 | File Upload | `/upload` (POST) → `/uploads`; served from `/static/uploads/` |
| 11 | Parameter Enumeration | `/debug?level=` (hidden `verbose`/`debug_token`/`admin`) |
| 12 | Virtual Host Enum | `Host:` header via middleware; `VHOSTS` dict |
| 13 | IDOR | `/profile`, `/api/profile`, `/api/orders`, `/api/account?ref=` (base64) |
