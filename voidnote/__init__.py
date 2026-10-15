"""
VoidNote SDK — Python

pip install voidnote

Works with Python 3.9+. Requires: cryptography

    pip install voidnote cryptography
"""

from __future__ import annotations

import email.utils
import hashlib
import http.client
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import json
from dataclasses import dataclass, field
from typing import Optional, Generator, Literal, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

DEFAULT_BASE = "https://voidnote.net"
__version__ = "0.5.0"
# Cloudflare refuses urllib's default "Python-urllib/x.y" agent (error 1010).
_USER_AGENT = f"voidnote-python/{__version__}"

# How a note's AES key is derived from the 32-hex secret in its link:
#   sha256:             key = SHA-256(secret bytes)
#   pbkdf2-sha256-600k: key = PBKDF2-HMAC-SHA256(password UTF-8, salt = secret bytes, 600000 iterations)
KDF_SHA256 = "sha256"
KDF_PBKDF2 = "pbkdf2-sha256-600k"
PBKDF2_ITERATIONS = 600_000
_KDFS = (KDF_SHA256, KDF_PBKDF2)


class VoidNoteError(RuntimeError):
    """
    Every failure the notes and streams API reports.

    code is one of:
      "http"              the server refused the request; see status and retry_after
      "not_found"         the note does not exist, expired, or its views are used up
      "password_required" the note needs a password; no view was used
      "unsupported_kdf"   the note uses a key derivation this SDK version cannot do; no view was used
      "decryption_failed" wrong password or link; the view was used
    """

    def __init__(self, message: str, code: str, status: Optional[int] = None, retry_after: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.retry_after = retry_after


@dataclass
class ReadResult:
    content: str
    title: Optional[str]
    view_count: int
    max_views: int
    destroyed: bool
    views_remaining: Optional[int] = None  # populated for v1 URLs
    kdf: Optional[str] = None              # populated for v1 URLs


@dataclass
class CreateResult:
    url: str        # full shareable URL — includes #secret for v1 notes
    token: str      # 32-char tokenId
    expires_at: str
    view_limit: int = 1
    kdf: str = KDF_SHA256


@dataclass
class PeekResult:
    exists: bool
    type: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    view_limit: Optional[int] = None
    views_remaining: Optional[int] = None
    kdf: Optional[str] = None


# --- internal helpers ---

def _parse_note_url(url_or_token: str) -> Tuple[str, Optional[Tuple[str, str]]]:
    """
    Returns (format, data) where:
      format = 'v1'     → data = (tokenId, secret)
      format = 'legacy' → data = None (fullToken is the 64-char token found in url)
    Raises ValueError if neither format matches.
    """
    # v1 format: .../n/{32-hex}#{32-hex}
    if '#' in url_or_token:
        before, _, secret = url_or_token.partition('#')
        token_id = before.rstrip('/').rsplit('/', 1)[-1]
        if (len(token_id) == 32 and re.fullmatch(r'[0-9a-f]+', token_id, re.I)
                and len(secret) == 32 and re.fullmatch(r'[0-9a-f]+', secret, re.I)):
            return 'v1', (token_id.lower(), secret.lower())
    # Legacy: 64-char hex token
    match = re.search(r'[0-9a-f]{64}', url_or_token, re.I)
    if match:
        return 'legacy', (match.group(0).lower(), None)
    raise ValueError("Invalid VoidNote URL or token — expected .../tokenId#secret or 64-char token")


def _generate_secret() -> str:
    return os.urandom(16).hex()


def _require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise ImportError(
            "The 'cryptography' package is required to encrypt and decrypt notes: "
            "pip install cryptography"
        )


def _derive_key(secret: str, kdf: str, password: Optional[str]) -> bytes:
    secret_bytes = bytes.fromhex(secret)
    if kdf == KDF_PBKDF2:
        if not password:
            raise VoidNoteError("VoidNote: this note needs a password", "password_required")
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), secret_bytes, PBKDF2_ITERATIONS, 32)
    return hashlib.sha256(secret_bytes).digest()


def _encrypt_with_key(content: str, key: bytes) -> Tuple[str, str]:
    _require_crypto()
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, content.encode("utf-8"), None)
    return ciphertext.hex(), iv.hex()


def _encrypt(content: str, secret: str) -> Tuple[str, str]:
    return _encrypt_with_key(content, _derive_key(secret, KDF_SHA256, None))


def _decrypt_note(enc_hex: str, iv_hex: str, secret: str, kdf: str, password: Optional[str]) -> str:
    _require_crypto()
    key = _derive_key(secret, kdf, password)
    try:
        plaintext = AESGCM(key).decrypt(bytes.fromhex(iv_hex), bytes.fromhex(enc_hex), None)
    except InvalidTag:
        raise VoidNoteError(
            "VoidNote: decryption failed — the link's key is wrong or incomplete"
            if kdf == KDF_SHA256
            else "VoidNote: decryption failed — wrong password (this read used a view)",
            "decryption_failed",
        ) from None
    return plaintext.decode("utf-8")


def _check_kdf(kdf: Optional[str]) -> str:
    name = kdf or KDF_SHA256
    if name not in _KDFS:
        raise VoidNoteError(
            f'VoidNote: this note uses key derivation "{name}", which this SDK version cannot decrypt — '
            "upgrade voidnote",
            "unsupported_kdf",
        )
    return name


def _positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _parse_body(raw: bytes) -> dict:
    """JSON body as a dict; a non-JSON body (proxy page, plain-text error) becomes {"error": text}."""
    text = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"error": text.strip()[:300]}
    return data if isinstance(data, dict) else {"data": data}


def _request(url: str, *, method: str = "GET", headers: dict | None = None, body: bytes | None = None):
    """(body as dict, HTTP status, response headers). HTTP errors are returned, not raised."""
    req = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": _USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req) as resp:
            return _parse_body(resp.read()), resp.status, resp.headers
    except urllib.error.HTTPError as e:
        return _parse_body(e.read()), e.code, e.headers


def _fetch(url: str, *, method: str = "GET", headers: dict | None = None, body: bytes | None = None):
    data, status, _ = _request(url, method=method, headers=headers, body=body)
    return data, status


def _retry_after(headers) -> Optional[int]:
    """Retry-After as seconds: either delta-seconds or an HTTP date."""
    value = (headers.get("Retry-After") if headers is not None else None) or ""
    value = value.strip()
    if value.isdigit():
        return int(value)
    if value:
        try:
            at = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        return max(0, int(at.timestamp() - time.time() + 0.999))
    return None


def _raise_for(data: dict, status: int, headers=None) -> None:
    if status >= 400:
        retry_after = _retry_after(headers)
        message = f"VoidNote: HTTP {status} — {data.get('error', 'request failed')}"
        if retry_after is not None:
            message += f" (retry after {retry_after}s)"
        raise VoidNoteError(message, "http", status, retry_after)


def _get_json(url: str, **kwargs) -> dict:
    data, status, headers = _request(url, **kwargs)
    _raise_for(data, status, headers)
    return data


# --- public API ---

def read(url_or_token: str, base: str = DEFAULT_BASE, *, password: Optional[str] = None) -> ReadResult:
    """
    Read and decrypt a VoidNote. Consumes one view.

    Accepts both v1 URLs (https://voidnote.net/n/{tokenId}#{secret})
    and legacy URLs (https://voidnote.net/note/{64-char-token}).

    v1 notes are checked first without using a view: a missing note, a note that
    needs a password when none was given, or an unknown key derivation raises
    VoidNoteError (code "not_found", "password_required", "unsupported_kdf") and
    the view stays unused. A wrong password is only detectable after the view is used.

    Args:
        url_or_token: Full VoidNote URL or raw 64-char hex token (legacy)
        base:         Override base URL (default: https://voidnote.net)
        password:     The sender's password, for notes created with one

    Example:
        result = voidnote.read("https://voidnote.net/n/TOKEN#SECRET")
        print(result.content)
        result = voidnote.read(url, password="correct horse")
    """
    fmt, data = _parse_note_url(url_or_token)

    if fmt == 'v1':
        token_id, secret = data
        meta = _get_json(f"{base}/api/v1/note/{token_id}/meta/")
        if not meta.get("exists"):
            raise VoidNoteError("VoidNote: note not found, expired or already destroyed", "not_found")
        meta_kdf = _check_kdf(meta.get("kdf"))
        if meta_kdf != KDF_SHA256 and not password:
            raise VoidNoteError(
                "VoidNote: this note needs a password — pass password= (no view was used)",
                "password_required",
            )

        resp = _get_json(f"{base}/api/v1/note/{token_id}/consume/")
        kdf = _check_kdf(resp.get("kdf") or meta_kdf)
        content = _decrypt_note(resp["encrypted"], resp["iv"], secret, kdf, password)
        views_remaining = resp.get("viewsRemaining", 0)
        max_views = meta.get("viewLimit") or views_remaining + 1
        return ReadResult(
            content=content,
            title=None,
            view_count=max_views - views_remaining,
            max_views=max_views,
            destroyed=resp.get("destroyed", False),
            views_remaining=views_remaining,
            kdf=kdf,
        )

    # Legacy: server decrypts and returns plaintext
    full_token = data[0]
    resp = _get_json(f"{base}/api/note/{full_token}/")
    return ReadResult(
        content=resp["content"],
        title=resp.get("title"),
        view_count=resp["viewCount"],
        max_views=resp["maxViews"],
        destroyed=resp["destroyed"],
    )


def peek(url_or_token: str, base: str = DEFAULT_BASE) -> PeekResult:
    """
    Peek at note metadata without consuming a view. kdf tells whether the note
    needs a password ("pbkdf2-sha256-600k") or not ("sha256").

    Example:
        meta = voidnote.peek("https://voidnote.net/n/TOKEN#SECRET")
        print(meta.views_remaining, meta.expires_at, meta.kdf)
    """
    # Extract tokenId: strip fragment, get last path segment
    without_fragment = url_or_token.split('#')[0].rstrip('/')
    last_seg = without_fragment.rsplit('/', 1)[-1]
    if len(last_seg) == 64 and re.fullmatch(r'[0-9a-f]+', last_seg, re.I):
        token_id = last_seg[:32].lower()  # legacy: take first half
    elif len(last_seg) == 32 and re.fullmatch(r'[0-9a-f]+', last_seg, re.I):
        token_id = last_seg.lower()
    else:
        raise ValueError(f"Cannot extract tokenId from input: {url_or_token!r}")

    resp = _get_json(f"{base}/api/v1/note/{token_id}/meta/")
    return PeekResult(
        exists=resp.get("exists", False),
        type=resp.get("type"),
        created_at=resp.get("createdAt"),
        expires_at=resp.get("expiresAt"),
        view_limit=resp.get("viewLimit"),
        views_remaining=resp.get("viewsRemaining"),
        kdf=resp.get("kdf"),
    )


def create(
    content: str,
    *,
    api_key: Optional[str] = None,
    password: Optional[str] = None,
    max_views: int = 1,
    expires_in: int = 1,
    base: str = DEFAULT_BASE,
) -> CreateResult:
    """
    Create a VoidNote using the v1 API. Encrypts content client-side — server never
    sees plaintext. Server generates the tokenId; client holds the secret in the URL fragment.

    No API key is needed: without one the note is anonymous, held to 168 hours and
    10 views, and rate-limited per IP. With a password the key is derived with
    PBKDF2 and the reader needs both the link and the password.

    Args:
        content:    The secret text to encrypt and store
        api_key:    Optional API key from a free account (vn_...): up to 720 hours and 100 views
        password:   Optional password the reader must also supply (kdf pbkdf2-sha256-600k)
        max_views:  How many times the note can be read (default 1)
        expires_in: Lifetime in hours (default 1)
        base:       Override base URL (default: https://voidnote.net)

    Returns:
        CreateResult with .url (includes #secret — share the full URL), .token and .kdf

    Raises:
        VoidNoteError with the server's message, e.g. HTTP 429 with .retry_after

    Example:
        result = voidnote.create("my-secret-api-key")
        print(result.url)  # https://voidnote.net/n/TOKEN#SECRET
    """
    if password == "":
        raise ValueError("password must not be empty")
    _positive_int("max_views", max_views)
    _positive_int("expires_in", expires_in)
    kdf = KDF_PBKDF2 if password else KDF_SHA256

    secret = _generate_secret()
    encrypted, iv = _encrypt_with_key(content, _derive_key(secret, kdf, password))

    payload = {
        "encrypted": encrypted,
        "iv": iv,
        "expiresIn": expires_in * 3600,  # hours → seconds
        "viewLimit": max_views,
        "kdf": kdf,
    }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    data = _get_json(f"{base}/api/v1/note/", method="POST", headers=headers, body=json.dumps(payload).encode("utf-8"))

    # Server returns URL without secret — append #secret
    server_url = data.get("url", f"{base}/n/{data.get('token', '')}")
    return CreateResult(
        url=f"{server_url}#{secret}",
        token=data.get("token", ""),
        expires_at=data.get("expiresAt", ""),
        view_limit=data.get("viewLimit", max_views),
        kdf=data.get("kdf", kdf),
    )


# ---------------------------------------------------------------------------
# Void Stream — live encrypted real-time channels
# ---------------------------------------------------------------------------

@dataclass
class StreamHandle:
    """
    A live Void Stream. Write encrypted messages, watch them appear in real time,
    close to self-destruct. write() and close() authenticate with the API key
    the stream was created with.
    """
    url: str
    expires_at: str
    _full_token: str = field(repr=False)
    _secret: str = field(repr=False)
    _base: str = field(repr=False, default=DEFAULT_BASE)
    _api_key: str = field(repr=False, default="")

    def _auth_headers(self) -> dict:
        if not self._api_key:
            raise RuntimeError("VoidNote: API key required to write to or close a broadcast stream")
        return {"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"}

    def write(self, content: str) -> None:
        """Encrypt and push a message to the stream."""
        encrypted_content, iv = _encrypt(content, self._secret)
        body = json.dumps({"encryptedContent": encrypted_content, "iv": iv}).encode()
        data, status = _fetch(
            f"{self._base}/api/stream/{self._full_token}/write/",
            method="POST",
            headers=self._auth_headers(),
            body=body,
        )
        _raise_for(data, status)

    def close(self) -> None:
        """Close the stream — viewers see a closed event and all content self-destructs."""
        data, status = _fetch(
            f"{self._base}/api/stream/{self._full_token}/close/",
            method="POST",
            headers=self._auth_headers(),
            body=b"{}",
        )
        _raise_for(data, status)

    def watch(self) -> Generator[str, None, None]:
        """Watch this stream locally. Yields decrypted messages."""
        yield from watch(self.url, base=self._base)


def create_stream(
    *,
    api_key: str,
    title: Optional[str] = None,
    ttl: Literal[3600, 21600, 86400] = 3600,
    base: str = DEFAULT_BASE,
) -> StreamHandle:
    """
    Create a new Void Stream. Requires an API key from a free account.

    Example:
        stream = voidnote.create_stream(api_key="vn_...", title="Deploy #42")
        print(stream.url)
        stream.write("Starting deployment...")
        stream.close()
    """
    full_token = os.urandom(32).hex()
    token_id = full_token[:32]
    secret = full_token[32:]

    payload = {"tokenId": token_id, "ttl": ttl}
    if title:
        payload["title"] = title

    data, status = _fetch(
        f"{base}/api/stream/",
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        body=json.dumps(payload).encode(),
    )
    _raise_for(data, status)
    if not data.get("success"):
        raise RuntimeError(f"VoidNote: {data.get('error', 'stream creation failed')}")

    url = f"{data['siteUrl']}/stream/{full_token}"
    return StreamHandle(
        url=url,
        expires_at=data.get("expiresAt", ""),
        _full_token=full_token,
        _secret=secret,
        _base=base,
        _api_key=api_key,
    )


def _join_stream(base: str, token: str, password: Optional[str]) -> Optional[str]:
    """Access token for reading a stream's events; None once the stream is closed or expired."""
    payload = {} if password is None else {"password": password}
    data, status = _fetch(
        f"{base}/api/stream/{token}/join/",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=json.dumps(payload).encode(),
    )
    if status == 410:
        return None
    _raise_for(data, status)
    access_token = data.get("accessToken")
    if not access_token:
        raise RuntimeError("VoidNote: join returned no access token")
    return access_token


# Consecutive network failures tolerated while reconnecting before watch() gives up.
_WATCH_MAX_RETRIES = 5


def watch(
    url_or_token: str,
    base: str = DEFAULT_BASE,
    *,
    password: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Watch a Void Stream. Yields decrypted messages as they arrive.
    Blocks until the stream is closed or expired. Joins the stream for an
    access token (re-joining when it expires) and reconnects with Last-Event-ID.
    Raises VoidNoteError on HTTP errors.

    Example:
        for message in voidnote.watch("https://voidnote.net/stream/abc123..."):
            print(message)
    """
    token = re.search(r'[0-9a-f]{64}', url_or_token, re.I)
    if not token:
        raise ValueError("No valid 64-char stream token found in input")
    token = token.group(0).lower()
    secret = token[32:64]
    key = hashlib.sha256(bytes.fromhex(secret)).digest()

    access_token = _join_stream(base, token, password)
    if access_token is None:
        return
    rejoined = False
    failures = 0
    last_id: Optional[str] = None

    while True:
        headers: dict = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "User-Agent": _USER_AGENT,
        }
        if last_id is not None:
            headers["Last-Event-ID"] = last_id

        query = urllib.parse.urlencode({"at": access_token})
        req = urllib.request.Request(f"{base}/api/stream/{token}/events/?{query}", headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                rejoined = False
                failures = 0
                event_id: Optional[str] = None
                event_data: Optional[str] = None

                for raw_line in resp:
                    line = raw_line.decode("utf-8").rstrip("\r\n")

                    if line.startswith("id: "):
                        event_id = line[4:]
                    elif line.startswith("data: "):
                        event_data = line[6:]
                    elif line == "" and event_data is not None:
                        if event_id is not None:
                            last_id = event_id

                        try:
                            data = json.loads(event_data)
                        except json.JSONDecodeError:
                            event_data = None
                            event_id = None
                            continue

                        if data.get("type") in ("closed", "expired"):
                            return

                        if "enc" in data and "iv" in data:
                            try:
                                content = _decrypt_stream_msg(data["enc"], data["iv"], key)
                                yield content
                            except Exception:
                                pass

                        event_data = None
                        event_id = None
        except urllib.error.HTTPError as e:
            # Access tokens live 30 minutes: re-join once, then give up on a repeat 401.
            if e.code == 401 and not rejoined:
                access_token = _join_stream(base, token, password)
                if access_token is None:
                    return
                rejoined = True
                continue
            _raise_for(_parse_body(e.read()), e.code, e.headers)
        except (OSError, http.client.HTTPException):
            failures += 1
            if failures > _WATCH_MAX_RETRIES:
                raise
            time.sleep(min(2 ** failures, 30))


def _decrypt_stream_msg(enc_hex: str, iv_hex: str, key: bytes) -> str:
    if not _HAS_CRYPTO:
        raise ImportError("pip install cryptography")
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(enc_hex)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


__all__ = [
    "read", "create", "peek", "ReadResult", "CreateResult", "PeekResult",
    "VoidNoteError", "KDF_SHA256", "KDF_PBKDF2", "PBKDF2_ITERATIONS",
    "create_stream", "watch", "StreamHandle",
]
