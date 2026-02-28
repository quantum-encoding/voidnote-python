"""
VoidNote SDK — Python

pip install voidnote

Works with Python 3.9+. Requires: cryptography

    pip install voidnote cryptography
"""

from __future__ import annotations

import hashlib
import os
import re
import urllib.request
import json
from dataclasses import dataclass, field
from typing import Optional, Generator, Literal

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

DEFAULT_BASE = "https://voidnote.net"


@dataclass
class ReadResult:
    content: str
    title: Optional[str]
    view_count: int
    max_views: int
    destroyed: bool


@dataclass
class CreateResult:
    url: str
    expires_at: str


# --- internal helpers ---

def _extract_token(url_or_token: str) -> str:
    match = re.search(r"[0-9a-f]{64}", url_or_token, re.IGNORECASE)
    if not match:
        raise ValueError("No valid 64-char token found in input")
    return match.group(0).lower()


def _generate_token() -> tuple[str, str, str]:
    token_bytes = os.urandom(32)
    full_token = token_bytes.hex()
    return full_token, full_token[:32], full_token[32:]


def _encrypt(content: str, secret: str) -> tuple[str, str]:
    if not _HAS_CRYPTO:
        raise ImportError(
            "The 'cryptography' package is required to create notes: "
            "pip install cryptography"
        )
    secret_bytes = bytes.fromhex(secret)
    key = hashlib.sha256(secret_bytes).digest()
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, content.encode("utf-8"), None)
    return ciphertext.hex(), iv.hex()


def _fetch(url: str, *, method: str = "GET", headers: dict | None = None, body: bytes | None = None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8")), resp.status


# --- public API ---

def read(url_or_token: str, base: str = DEFAULT_BASE) -> ReadResult:
    """
    Read a VoidNote. Consumes one view.

    Args:
        url_or_token: Full VoidNote URL or raw 64-char hex token
        base:         Override base URL (default: https://voidnote.net)

    Returns:
        ReadResult with .content, .title, .view_count, .max_views, .destroyed

    Example:
        result = voidnote.read("https://voidnote.net/note/abc123...")
        print(result.content)
    """
    token = _extract_token(url_or_token)
    data, status = _fetch(f"{base}/api/note/{token}")
    if status >= 400:
        raise RuntimeError(data.get("error", f"HTTP {status}"))
    return ReadResult(
        content=data["content"],
        title=data.get("title"),
        view_count=data["viewCount"],
        max_views=data["maxViews"],
        destroyed=data["destroyed"],
    )


def create(
    content: str,
    *,
    api_key: str,
    title: Optional[str] = None,
    max_views: int = 1,
    expires_in: int = 24,
    note_type: Literal["secure", "pipe"] = "secure",
    base: str = DEFAULT_BASE,
) -> CreateResult:
    """
    Create a VoidNote. Encrypts content client-side — the server never sees plaintext.

    Args:
        content:    The secret text to encrypt and store
        api_key:    Your API key from dashboard (vn_...)
        title:      Optional plaintext title (keep non-sensitive)
        max_views:  How many times the note can be read (1–100)
        expires_in: Lifetime in hours — one of: 1, 6, 24, 72, 168, 720
        note_type:  "secure" (default) or "pipe"
        base:       Override base URL (default: https://voidnote.net)

    Returns:
        CreateResult with .url (shareable link) and .expires_at

    Example:
        result = voidnote.create("my-secret-api-key", api_key="vn_...")
        print(result.url)
    """
    if not 1 <= max_views <= 100:
        raise ValueError("max_views must be between 1 and 100")
    if expires_in not in (1, 6, 24, 72, 168, 720):
        raise ValueError("expires_in must be one of: 1, 6, 24, 72, 168, 720")

    full_token, token_id, secret = _generate_token()
    encrypted_content, iv = _encrypt(content, secret)

    payload = {
        "tokenId": token_id,
        "encryptedContent": encrypted_content,
        "iv": iv,
        "maxViews": max_views,
        "expiresIn": expires_in,
        "noteType": note_type,
    }
    if title:
        payload["title"] = title

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    data, status = _fetch(f"{base}/api/notes", method="POST", headers=headers, body=body)
    if status >= 400 or not data.get("success"):
        raise RuntimeError(data.get("error", f"HTTP {status}"))

    return CreateResult(
        url=f"{data['siteUrl']}/note/{full_token}",
        expires_at=data["expiresAt"],
    )


# ---------------------------------------------------------------------------
# Void Stream — live encrypted real-time channels
# ---------------------------------------------------------------------------

@dataclass
class StreamHandle:
    """
    A live Void Stream. Write encrypted messages, watch them appear in real time,
    close to self-destruct.

    Returned by create_stream(). The URL contains the decryption key — share it
    with viewers. The server never sees plaintext.

    Example:
        stream = voidnote.create_stream(api_key="vn_...", title="Deploy run #42")
        print(stream.url)  # share with your viewer
        stream.write("Deployment starting…")
        stream.write("Build complete — 47/47 passed")
        stream.close()
    """
    url: str
    expires_at: str
    _full_token: str = field(repr=False)
    _secret: str = field(repr=False)
    _base: str = field(repr=False, default=DEFAULT_BASE)

    def write(self, content: str) -> None:
        """Encrypt and push a message to the stream."""
        if not _HAS_CRYPTO:
            raise ImportError("pip install cryptography")
        encrypted_content, iv = _encrypt(content, self._secret)
        body = json.dumps({"encryptedContent": encrypted_content, "iv": iv}).encode()
        data, status = _fetch(
            f"{self._base}/api/stream/{self._full_token}/write",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        if status >= 400 or not data.get("success"):
            raise RuntimeError(data.get("error", f"HTTP {status}"))

    def close(self) -> None:
        """Close the stream — viewers see a closed event and all content self-destructs."""
        _fetch(
            f"{self._base}/api/stream/{self._full_token}/close",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=b"{}",
        )

    def watch(self) -> Generator[str, None, None]:
        """
        Watch this stream locally (writer-side). Yields decrypted messages.
        Useful for testing or observing your own stream.
        """
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

    Args:
        api_key: Your API key (vn_...) from the dashboard
        title:   Optional plaintext title
        ttl:     Lifetime in seconds: 3600 (1h), 21600 (6h), or 86400 (24h)
        base:    Override base URL

    Returns:
        StreamHandle with .url, .write(), .close(), .watch()

    Example:
        stream = voidnote.create_stream(api_key="vn_...", title="Deploy #42")
        print(stream.url)
        stream.write("Starting deployment...")
        stream.close()
    """
    full_token, token_id, secret = _generate_token()

    payload = {"tokenId": token_id, "ttl": ttl}
    if title:
        payload["title"] = title

    data, status = _fetch(
        f"{base}/api/stream",
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        body=json.dumps(payload).encode(),
    )
    if status >= 400 or not data.get("success"):
        raise RuntimeError(data.get("error", f"HTTP {status}"))

    url = f"{data['siteUrl']}/stream/{full_token}"
    return StreamHandle(
        url=url,
        expires_at=data.get("expiresAt", ""),
        _full_token=full_token,
        _secret=secret,
        _base=base,
    )


def watch(url_or_token: str, base: str = DEFAULT_BASE) -> Generator[str, None, None]:
    """
    Watch a Void Stream. Yields decrypted messages as they arrive.
    Blocks until the stream is closed or expired.
    Automatically reconnects on disconnect using Last-Event-ID.

    Args:
        url_or_token: Full stream URL or raw 64-char token
        base:         Override base URL

    Example:
        for message in voidnote.watch("https://voidnote.net/stream/abc123..."):
            print(message)
    """
    token = _extract_token(url_or_token)
    secret = token[32:64]
    key = hashlib.sha256(bytes.fromhex(secret)).digest()

    last_id: Optional[str] = None

    while True:
        headers: dict = {"Accept": "text/event-stream", "Cache-Control": "no-cache"}
        if last_id is not None:
            headers["Last-Event-ID"] = last_id

        req = urllib.request.Request(f"{base}/api/stream/{token}/events", headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
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
                                pass  # tampered or wrong key

                        event_data = None
                        event_id = None
        except Exception:
            if last_id is None:
                raise
            # Reconnect on transient failure
            continue


def _decrypt_stream_msg(enc_hex: str, iv_hex: str, key: bytes) -> str:
    """Decrypt a single stream message using pre-derived AES key."""
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
    amount: str        # human-readable, e.g. "5.000000"
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
    """
    Create a crypto payment order for credits.
    Returns an address and exact amount to send — valid for 1 hour.

    Args:
        api_key:   Your API key (vn_...) from the dashboard
        bundle_id: "test" ($1/20), "starter" ($5/100), "standard" ($20/500), "pro" ($35/1000)
        chain:     Payment network
        token:     Token to send
        base:      Override base URL

    Example:
        order = voidnote.create_crypto_order(
            api_key="vn_...", bundle_id="starter", chain="polygon", token="USDT"
        )
        print(f"Send {order.amount} {order.token} to {order.to_address}")
    """
    body = json.dumps({"bundleId": bundle_id, "chain": chain, "token": token}).encode()
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    data, status = _fetch(f"{base}/api/buy/crypto/create-order", method="POST", headers=headers, body=body)
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
    """
    Submit a transaction hash to confirm a crypto payment.
    Verifies on-chain and credits your account instantly.

    Args:
        api_key:  Your API key (vn_...) from the dashboard
        order_id: Order ID from create_crypto_order()
        tx_hash:  Transaction hash from your wallet
        base:     Override base URL

    Example:
        result = voidnote.submit_crypto_payment(
            api_key="vn_...", order_id=order.order_id, tx_hash="0x..."
        )
        print(f"New balance: {result.credits} credits")
    """
    body = json.dumps({"orderId": order_id, "txHash": tx_hash}).encode()
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    data, status = _fetch(f"{base}/api/buy/crypto/submit-tx", method="POST", headers=headers, body=body)
    if status >= 400:
        raise RuntimeError(data.get("error", f"HTTP {status}"))
    return SubmitPaymentResult(credits=data["credits"], credits_added=data["creditsAdded"])


__all__ = [
    "read", "create", "ReadResult", "CreateResult",
    "create_stream", "watch", "StreamHandle",
    "CryptoOrder", "SubmitPaymentResult", "create_crypto_order", "submit_crypto_payment",
]
