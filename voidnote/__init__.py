"""
VoidNote SDK — Python

pip install voidnote

Works with Python 3.9+. Requires: cryptography

    pip install voidnote cryptography
"""

from __future__ import annotations

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
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

DEFAULT_BASE = "https://voidnote.net"
__version__ = "0.4.1"
# Cloudflare refuses urllib's default "Python-urllib/x.y" agent (error 1010).
_USER_AGENT = f"voidnote-python/{__version__}"


@dataclass
class ReadResult:
    content: str
    title: Optional[str]
    view_count: int
    max_views: int
    destroyed: bool
    views_remaining: Optional[int] = None  # populated for v1 URLs


@dataclass
class CreateResult:
    url: str        # full shareable URL — includes #secret for v1 notes
    token: str      # 32-char tokenId
    expires_at: str


@dataclass
class PeekResult:
    exists: bool
    type: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    view_limit: Optional[int] = None
    views_remaining: Optional[int] = None


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


def _encrypt(content: str, secret: str) -> Tuple[str, str]:
    if not _HAS_CRYPTO:
        raise ImportError(
            "The 'cryptography' package is required to create notes: "
            "pip install cryptography"
        )
    key = hashlib.sha256(bytes.fromhex(secret)).digest()
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, content.encode("utf-8"), None)
    return ciphertext.hex(), iv.hex()


def _decrypt(enc_hex: str, iv_hex: str, secret: str) -> str:
    if not _HAS_CRYPTO:
        raise ImportError("pip install cryptography")
    key = hashlib.sha256(bytes.fromhex(secret)).digest()
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(enc_hex)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None).decode("utf-8")


def _parse_body(raw: bytes) -> dict:
    """JSON body as a dict; a non-JSON body (proxy page, plain-text error) becomes {"error": text}."""
    text = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"error": text.strip()[:300]}
    return data if isinstance(data, dict) else {"data": data}


def _fetch(url: str, *, method: str = "GET", headers: dict | None = None, body: bytes | None = None):
    req = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": _USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req) as resp:
            return _parse_body(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return _parse_body(e.read()), e.code


def _raise_for(data: dict, status: int) -> None:
    if status >= 400:
        raise RuntimeError(f"VoidNote: HTTP {status} — {data.get('error', 'request failed')}")


# --- public API ---

def read(url_or_token: str, base: str = DEFAULT_BASE) -> ReadResult:
    """
    Read and decrypt a VoidNote. Consumes one view.

    Accepts both v1 URLs (https://voidnote.net/n/{tokenId}#{secret})
    and legacy URLs (https://voidnote.net/note/{64-char-token}).

    Example:
        result = voidnote.read("https://voidnote.net/n/TOKEN#SECRET")
        print(result.content)
    """
    fmt, data = _parse_note_url(url_or_token)

    if fmt == 'v1':
        token_id, secret = data
        resp, status = _fetch(f"{base}/api/v1/note/{token_id}/consume/")
        if status >= 400:
            raise RuntimeError(resp.get("error", f"HTTP {status}"))
        content = _decrypt(resp["encrypted"], resp["iv"], secret)
        views_remaining = resp.get("viewsRemaining", 0)
        return ReadResult(
            content=content,
            title=None,
            view_count=1,
            max_views=views_remaining + 1,
            destroyed=resp.get("destroyed", False),
            views_remaining=views_remaining,
        )

    # Legacy: server decrypts and returns plaintext
    full_token = data[0]
    resp, status = _fetch(f"{base}/api/note/{full_token}/")
    if status >= 400:
        raise RuntimeError(resp.get("error", f"HTTP {status}"))
    return ReadResult(
        content=resp["content"],
        title=resp.get("title"),
        view_count=resp["viewCount"],
        max_views=resp["maxViews"],
        destroyed=resp["destroyed"],
    )


def peek(url_or_token: str, base: str = DEFAULT_BASE) -> PeekResult:
    """
    Peek at note metadata without consuming a view.

    Example:
        meta = voidnote.peek("https://voidnote.net/n/TOKEN#SECRET")
        print(meta.views_remaining, meta.expires_at)
    """
    # Extract tokenId: strip fragment, get last path segment
    without_fragment = url_or_token.split('#')[0].rstrip('/')
    last_seg = without_fragment.rsplit('/', 1)[-1]
    if len(last_seg) == 64 and re.fullmatch(r'[0-9a-f]+', last_seg, re.I):
        token_id = last_seg[:32]  # legacy: take first half
    elif len(last_seg) == 32 and re.fullmatch(r'[0-9a-f]+', last_seg, re.I):
        token_id = last_seg.lower()
    else:
        raise ValueError(f"Cannot extract tokenId from input: {url_or_token!r}")

    resp, status = _fetch(f"{base}/api/v1/note/{token_id}/meta/")
    if status >= 400:
        raise RuntimeError(resp.get("error", f"HTTP {status}"))
    return PeekResult(
        exists=resp.get("exists", False),
        type=resp.get("type"),
        created_at=resp.get("createdAt"),
        expires_at=resp.get("expiresAt"),
        view_limit=resp.get("viewLimit"),
        views_remaining=resp.get("viewsRemaining"),
    )


def create(
    content: str,
    *,
    api_key: str,
    max_views: int = 1,
    expires_in: int = 1,
    base: str = DEFAULT_BASE,
) -> CreateResult:
    """
    Create a VoidNote using the v1 API. Encrypts content client-side — server never
    sees plaintext. Server generates the tokenId; client holds the secret in the URL fragment.

    Args:
        content:    The secret text to encrypt and store
        api_key:    Your API key from dashboard (vn_...)
        max_views:  How many times the note can be read (1–100)
        expires_in: Lifetime in hours (1–720, default 1)
        base:       Override base URL (default: https://voidnote.net)

    Returns:
        CreateResult with .url (includes #secret — share the full URL) and .token

    Example:
        result = voidnote.create("my-secret-api-key", api_key="vn_...")
        print(result.url)  # https://voidnote.net/n/TOKEN#SECRET
    """
    if not 1 <= max_views <= 100:
        raise ValueError("max_views must be between 1 and 100")
    if not 1 <= expires_in <= 720:
        raise ValueError("expires_in must be between 1 and 720 hours")

    secret = _generate_secret()
    encrypted, iv = _encrypt(content, secret)

    payload = {
        "encrypted": encrypted,
        "iv": iv,
        "expiresIn": expires_in * 3600,  # hours → seconds
        "viewLimit": max_views,
    }

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    data, status = _fetch(f"{base}/api/v1/note/", method="POST", headers=headers, body=body)
    if status >= 400:
        raise RuntimeError(data.get("error", f"HTTP {status}"))

    # Server returns URL without secret — append #secret
    server_url = data.get("url", f"{base}/n/{data.get('token', '')}")
    return CreateResult(
        url=f"{server_url}#{secret}",
        token=data.get("token", ""),
        expires_at=data.get("expiresAt", ""),
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
    Create a new Void Stream. Costs 1 credit.

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
    Raises RuntimeError on HTTP errors.

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
            _raise_for(_parse_body(e.read()), e.code)
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


# ---------------------------------------------------------------------------
# Buy / Credits API
# ---------------------------------------------------------------------------

@dataclass
class CryptoOrder:
    order_id: str
    to_address: str
    chain: str
    token: str
    amount: str
    amount_usd: float
    credits: int
    expires_at: str


@dataclass
class SubmitPaymentResult:
    credits: int
    credits_added: int


def create_crypto_order(
    *,
    api_key: str,
    bundle_id: Literal["test", "starter", "standard", "pro"],
    chain: Literal["polygon", "base", "arbitrum", "ethereum", "bitcoin", "tron"],
    token: Literal["USDT", "USDC", "ETH", "BTC", "TRX"],
    base: str = DEFAULT_BASE,
) -> CryptoOrder:
    """Create a crypto payment order for credits."""
    body = json.dumps({"bundleId": bundle_id, "chain": chain, "token": token}).encode()
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    data, status = _fetch(f"{base}/api/buy/crypto/create-order/", method="POST", headers=headers, body=body)
    if status >= 400:
        raise RuntimeError(data.get("error", f"HTTP {status}"))
    return CryptoOrder(
        order_id=data["orderId"],
        to_address=data["toAddress"],
        chain=data["chain"],
        token=data["token"],
        amount=data["amount"],
        amount_usd=data["amountUsd"],
        credits=data["credits"],
        expires_at=data["expiresAt"],
    )


def submit_crypto_payment(
    *,
    api_key: str,
    order_id: str,
    tx_hash: str,
    base: str = DEFAULT_BASE,
) -> SubmitPaymentResult:
    """Submit a transaction hash to confirm a crypto payment."""
    body = json.dumps({"orderId": order_id, "txHash": tx_hash}).encode()
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    data, status = _fetch(f"{base}/api/buy/crypto/submit-tx/", method="POST", headers=headers, body=body)
    if status >= 400:
        raise RuntimeError(data.get("error", f"HTTP {status}"))
    return SubmitPaymentResult(credits=data["credits"], credits_added=data["creditsAdded"])


__all__ = [
    "read", "create", "peek", "ReadResult", "CreateResult", "PeekResult",
    "create_stream", "watch", "StreamHandle",
    "CryptoOrder", "SubmitPaymentResult", "create_crypto_order", "submit_crypto_payment",
]
