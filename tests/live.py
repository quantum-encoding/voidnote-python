"""
Live round trip against voidnote.net (creates real anonymous notes).
Run from python/:  uv run --no-project --with cryptography --with-editable . python tests/live.py [in.json] [out.json]
in.json holds notes another SDK created; this script reads them (cross-language),
then creates its own and writes them to out.json for the next SDK.
"""

import json
import os
import sys

import voidnote
from voidnote import VoidNoteError

LANG = "python"
PASSWORD = "pässwörd-日本🔑"
BASE = os.environ.get("VOIDNOTE_BASE", "https://voidnote.net")
args = [a for a in sys.argv[1:] if not a.startswith("--")]
in_file = args[0] if args else None
out_file = args[1] if len(args) > 1 else None


def ok(step):
    print(f"PASS {LANG}: {step}", flush=True)


def expect_error(fn):
    try:
        fn()
    except VoidNoteError as e:
        return e
    raise AssertionError("expected VoidNoteError")


if in_file and os.path.exists(in_file):
    prev = json.load(open(in_file, encoding="utf-8"))
    a = voidnote.read(prev["sha256"], BASE)
    assert (a.content, a.kdf, a.destroyed) == (prev["content_sha256"], "sha256", True), a
    ok(f"read {prev['from']} sha256 note (cross-language), destroyed on last view")
    b = voidnote.read(prev["pbkdf2"], BASE, password=prev["password"])
    assert (b.content, b.kdf, b.destroyed) == (prev["content_pbkdf2"], "pbkdf2-sha256-600k", True), b
    ok(f"read {prev['from']} pbkdf2 note with non-ASCII password (cross-language)")

if "--read-only" not in sys.argv:
    out = {"from": LANG, "password": PASSWORD}

    out["content_sha256"] = f"live sha256 from {LANG} — ✓ 日本"
    s = voidnote.create(out["content_sha256"], max_views=2, base=BASE)
    assert s.kdf == "sha256"
    m = voidnote.peek(s.url, BASE)
    assert (m.exists, m.kdf, m.views_remaining) == (True, "sha256", 2), m
    r = voidnote.read(s.url, BASE)
    assert (r.content, r.views_remaining) == (out["content_sha256"], 1), r
    out["sha256"] = s.url
    ok("anonymous sha256 create → peek → read")

    out["content_pbkdf2"] = f"live pbkdf2 from {LANG} — 🔒"
    p = voidnote.create(out["content_pbkdf2"], password=PASSWORD, max_views=2, base=BASE)
    assert p.kdf == "pbkdf2-sha256-600k"
    assert voidnote.peek(p.url, BASE).kdf == "pbkdf2-sha256-600k"
    e = expect_error(lambda: voidnote.read(p.url, BASE))
    assert e.code == "password_required", e.code
    assert voidnote.peek(p.url, BASE).views_remaining == 2
    ok("pbkdf2 read without password refused before consume (views still 2)")
    r = voidnote.read(p.url, BASE, password=PASSWORD)
    assert (r.content, r.views_remaining) == (out["content_pbkdf2"], 1), r
    out["pbkdf2"] = p.url
    ok("anonymous pbkdf2 create → read with non-ASCII password")

    e = expect_error(lambda: voidnote.create("x", api_key="vn_invalid_live_check", base=BASE))
    assert e.status == 401 and "Invalid API key." in str(e), e
    ok('invalid API key surfaces 401 "Invalid API key."')

    if "--limits" in sys.argv:
        e = expect_error(lambda: voidnote.create("x", max_views=11, base=BASE))
        assert e.status == 400 and "viewLimit must be 1–10 without an account." in str(e), e
        ok(f"anonymous view limit surfaces the server's 400 message: {e}")

    if out_file:
        json.dump(out, open(out_file, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
