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
from dataclasses import dataclass
from typing import Optional

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
    base: str = DEFAULT_BASE,
) -> CreateResult:
    """
    Create a VoidNote. Encrypts content client-side — the server never sees plaintext.

    Args:
        content:   The secret text to encrypt and store
        api_key:   Your API key from dashboard (vn_...)
        title:     Optional plaintext title (keep non-sensitive)
        max_views: How many times the note can be read (1–100)
        base:      Override base URL (default: https://voidnote.net)

    Returns:
        CreateResult with .url (shareable link) and .expires_at

    Example:
        result = voidnote.create("my-secret-api-key", api_key="vn_...")
        print(result.url)
    """
    if not 1 <= max_views <= 100:
        raise ValueError("max_views must be between 1 and 100")

    full_token, token_id, secret = _generate_token()
    encrypted_content, iv = _encrypt(content, secret)

    payload = {
        "tokenId": token_id,
        "encryptedContent": encrypted_content,
        "iv": iv,
        "maxViews": max_views,
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


__all__ = ["read", "create", "ReadResult", "CreateResult"]
