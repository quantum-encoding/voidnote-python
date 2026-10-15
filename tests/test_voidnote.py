"""Unit tests against a mocked urllib. Run: uv run --with pytest --with cryptography pytest tests"""

import hashlib
import io
import json
import urllib.error
import urllib.request
from email.message import Message

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import voidnote
from voidnote import VoidNoteError

# Cross-client known answers shared with the iOS and Android suites
# (secret, iv and ciphertexts produced with WebCrypto).
KAT_SECRET = "00112233445566778899aabbccddeeff"
KAT_IV = "a1b2c3d4e5f6000102030405"
KAT_SHA256 = ("8f6ee0eb13334ea99cf53aa86bf4dc0fa4686b9c74f1bf98f3aa4bc216d70fc058ba9452266c57c681a5",
              "voidnote-v1-sha256-kat ✓")
KAT_PBKDF2 = ("3ca068b802bd8f8d25145619048f5de9b50ae3319ad9bc9f6af38bd9980107a311fb228dfd0b3e6b2c24",
              "correct horse battery staple", "voidnote-v1-pbkdf2-kat ✓")
KAT_UNICODE = ("c9aa7b0cd91b24f9c7982e6c0acb6233391307fc327b512c1ec87571aa62dbc5",
               "pässwörd-日本", "unicode password")
TOKEN = "0123456789abcdef0123456789abcdef"
BASE = "https://vn.test"
URL = f"{BASE}/n/{TOKEN}#{KAT_SECRET}"


class _Resp:
    def __init__(self, body: dict, status: int, headers: dict):
        self._body = json.dumps(body).encode()
        self.status = status
        self.headers = Message()
        for k, v in headers.items():
            self.headers[k] = v

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def server(monkeypatch):
    """Routes keyed by URL suffix → (body, status, headers). Records every request."""
    state = {"routes": {}, "calls": []}

    def urlopen(req, timeout=None):
        state["calls"].append(req)
        for suffix, handler in state["routes"].items():
            if req.full_url.endswith(suffix):
                body, status, headers = handler(req)
                if status >= 400:
                    hdrs = Message()
                    for k, v in headers.items():
                        hdrs[k] = v
                    raise urllib.error.HTTPError(req.full_url, status, "err", hdrs, io.BytesIO(json.dumps(body).encode()))
                return _Resp(body, status, headers)
        raise AssertionError(f"unexpected request {req.full_url}")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return state


def meta(kdf, **extra):
    return lambda req: ({"token": TOKEN, "exists": True, "type": "note", "viewLimit": 2,
                         "viewsRemaining": 2, "kdf": kdf, **extra}, 200, {})


def consume(kdf, encrypted):
    return lambda req: ({"token": TOKEN, "encrypted": encrypted, "iv": KAT_IV, "kdf": kdf, "consumed": True,
                         "viewsRemaining": 1, "destroyed": False}, 200, {})


def create_route(captured):
    def handler(req):
        captured["body"] = json.loads(req.data)
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        b = captured["body"]
        return ({"token": TOKEN, "url": f"{BASE}/n/{TOKEN}", "expiresAt": "2026-10-15 12:00:00",
                 "viewLimit": b["viewLimit"], "kdf": b["kdf"]}, 201, {})
    return handler


def open_created(captured, url, password=None):
    secret = bytes.fromhex(url.split("#")[1])
    if captured["body"]["kdf"] == "sha256":
        key = hashlib.sha256(secret).digest()
    else:
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), secret, 600_000, 32)
    b = captured["body"]
    return AESGCM(key).decrypt(bytes.fromhex(b["iv"]), bytes.fromhex(b["encrypted"]), None).decode()


# --- create ---

def test_create_without_key_is_anonymous(server):
    cap = {}
    server["routes"]["/api/v1/note/"] = create_route(cap)
    res = voidnote.create("hello", base=BASE)
    assert "authorization" not in cap["headers"]
    assert (cap["body"]["expiresIn"], cap["body"]["viewLimit"], cap["body"]["kdf"]) == (3600, 1, "sha256")
    assert res.url.startswith(f"{BASE}/n/{TOKEN}#") and len(res.url.split("#")[1]) == 32
    assert res.kdf == "sha256" and res.view_limit == 1
    assert open_created(cap, res.url) == "hello"


def test_create_with_key_sends_bearer(server):
    cap = {}
    server["routes"]["/api/v1/note/"] = create_route(cap)
    voidnote.create("hello", api_key="vn_test", base=BASE)
    assert cap["headers"]["authorization"] == "Bearer vn_test"


def test_create_with_password_uses_pbkdf2(server):
    cap = {}
    server["routes"]["/api/v1/note/"] = create_route(cap)
    res = voidnote.create("guarded", password="pässwörd-日本", max_views=3, expires_in=2, base=BASE)
    assert cap["body"]["kdf"] == "pbkdf2-sha256-600k"
    assert (cap["body"]["viewLimit"], cap["body"]["expiresIn"]) == (3, 7200)
    assert res.kdf == "pbkdf2-sha256-600k"
    assert open_created(cap, res.url, "pässwörd-日本") == "guarded"


def test_create_refuses_empty_password(server):
    with pytest.raises(ValueError):
        voidnote.create("x", password="", base=BASE)
    assert server["calls"] == []


def test_create_surfaces_429_retry_after(server):
    server["routes"]["/api/v1/note/"] = lambda req: (
        {"error": "Too many notes created. Try again shortly."}, 429, {"Retry-After": "60"})
    with pytest.raises(VoidNoteError) as exc:
        voidnote.create("x", base=BASE)
    e = exc.value
    assert (e.code, e.status, e.retry_after) == ("http", 429, 60)
    assert "Too many notes created" in str(e)
    assert isinstance(e, RuntimeError)


def test_create_surfaces_400_limit_message(server):
    server["routes"]["/api/v1/note/"] = lambda req: (
        {"error": "viewLimit must be 1–10 without an account."}, 400, {})
    with pytest.raises(VoidNoteError, match="viewLimit must be 1–10 without an account"):
        voidnote.create("x", max_views=50, base=BASE)


# --- read ---

def test_read_sha256_kat(server):
    server["routes"].update({"/meta/": meta("sha256"), "/consume/": consume("sha256", KAT_SHA256[0])})
    note = voidnote.read(URL, BASE)
    assert note.content == KAT_SHA256[1]
    assert (note.kdf, note.max_views, note.view_count, note.views_remaining) == ("sha256", 2, 1, 1)


def test_read_pbkdf2_kat(server):
    server["routes"].update({"/meta/": meta("pbkdf2-sha256-600k"),
                             "/consume/": consume("pbkdf2-sha256-600k", KAT_PBKDF2[0])})
    note = voidnote.read(URL, BASE, password=KAT_PBKDF2[1])
    assert note.content == KAT_PBKDF2[2]
    assert note.kdf == "pbkdf2-sha256-600k"


def test_read_unicode_password_kat(server):
    server["routes"].update({"/meta/": meta("pbkdf2-sha256-600k"),
                             "/consume/": consume("pbkdf2-sha256-600k", KAT_UNICODE[0])})
    assert voidnote.read(URL, BASE, password=KAT_UNICODE[1]).content == KAT_UNICODE[2]


def test_read_password_note_without_password_fails_before_consume(server):
    server["routes"].update({"/meta/": meta("pbkdf2-sha256-600k"),
                             "/consume/": consume("pbkdf2-sha256-600k", KAT_PBKDF2[0])})
    with pytest.raises(VoidNoteError) as exc:
        voidnote.read(URL, BASE)
    assert exc.value.code == "password_required"
    assert not any("/consume/" in c.full_url for c in server["calls"])


def test_read_wrong_password(server):
    server["routes"].update({"/meta/": meta("pbkdf2-sha256-600k"),
                             "/consume/": consume("pbkdf2-sha256-600k", KAT_PBKDF2[0])})
    with pytest.raises(VoidNoteError) as exc:
        voidnote.read(URL, BASE, password="wrong")
    assert exc.value.code == "decryption_failed"


def test_read_unknown_kdf_fails_before_consume(server):
    server["routes"].update({"/meta/": meta("argon2id"), "/consume/": consume("argon2id", KAT_SHA256[0])})
    with pytest.raises(VoidNoteError) as exc:
        voidnote.read(URL, BASE, password="x")
    assert exc.value.code == "unsupported_kdf"
    assert not any("/consume/" in c.full_url for c in server["calls"])


def test_read_missing_note(server):
    server["routes"]["/meta/"] = lambda req: ({"token": TOKEN, "exists": False}, 200, {})
    with pytest.raises(VoidNoteError) as exc:
        voidnote.read(URL, BASE)
    assert exc.value.code == "not_found"
    assert len(server["calls"]) == 1


def test_read_surfaces_410(server):
    server["routes"].update({"/meta/": meta("sha256"),
                             "/consume/": lambda req: ({"error": "Note not found or already destroyed."}, 410, {})})
    with pytest.raises(VoidNoteError, match="already destroyed") as exc:
        voidnote.read(URL, BASE)
    assert exc.value.status == 410


# --- peek ---

def test_peek_exposes_kdf(server):
    server["routes"]["/meta/"] = meta("pbkdf2-sha256-600k")
    m = voidnote.peek(URL, BASE)
    assert (m.kdf, m.views_remaining) == ("pbkdf2-sha256-600k", 2)
