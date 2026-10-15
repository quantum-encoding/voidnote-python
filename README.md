# voidnote

Official Python SDK for [VoidNote](https://voidnote.net): zero-knowledge self-destructing notes and live encrypted streams.

**v0.5.0** · Python 3.9+ · no account needed for notes

## Install

```bash
pip install voidnote
```

## Quick start

```python
import voidnote

# No account or API key needed. Content is encrypted locally; the server never sees it.
note = voidnote.create("my secret value")
print(note.url)    # https://voidnote.net/n/<tokenId>#<secret>

print(voidnote.read(note.url).content)
```

## API

### `voidnote.create(content, *, api_key=None, password=None, max_views=1, expires_in=1) → CreateResult`

Encrypt `content` locally and store the ciphertext. `expires_in` is in hours.

```python
result = voidnote.create("deploy key: abc123", max_views=3, expires_in=6)
print(result.url)        # full shareable URL, includes #secret
print(result.token)      # 32-char tokenId only
print(result.expires_at, result.view_limit, result.kdf)
```

Without an API key the note is anonymous: up to 168 hours (7 days) and 10 views, rate-limited per IP. An API key from a free account raises that to 720 hours and 100 views:

```python
voidnote.create("deploy key: abc123", api_key="vn_...", max_views=50, expires_in=720)
```

Add a password and the reader needs it as well as the link. The key is then PBKDF2-HMAC-SHA256 (600,000 iterations) of the password, salted with the link's secret:

```python
guarded = voidnote.create("db password: hunter2", password="correct horse")
# share guarded.url and the password through different channels
```

### `voidnote.read(url, *, password=None) → ReadResult`

Fetch and decrypt a note. Consumes one view. Accepts v1 URLs (`/n/<token>#<secret>`) and legacy URLs.

```python
note = voidnote.read("https://voidnote.net/n/<tokenId>#<secret>")
print(note.content)         # decrypted plaintext
print(note.views_remaining) # views left after this read
print(note.destroyed)       # True if this was the last view

# A note created with a password
guarded = voidnote.read(url, password="correct horse")
```

Before using a view, `read` checks the note's metadata. A missing note, a password note read without a password, or an unknown key derivation raises without touching the view. A wrong password can only be detected after decrypting, so it does use the view.

### `voidnote.peek(url) → PeekResult`

Check metadata without consuming a view. `kdf` is `"pbkdf2-sha256-600k"` when the note needs a password.

```python
meta = voidnote.peek("https://voidnote.net/n/<tokenId>#<secret>")
print(meta.exists, meta.views_remaining, meta.expires_at, meta.kdf)
```

### Errors

Failures raise `voidnote.VoidNoteError` (a `RuntimeError`) with a `code`:

| code | meaning |
|------|---------|
| `http` | the server refused; `status` and the server's message, plus `retry_after` (seconds) on 429 |
| `not_found` | the note doesn't exist, expired, or its views are used up |
| `password_required` | the note needs a password; no view was used |
| `unsupported_kdf` | the note uses a key derivation this version can't do; no view was used |
| `decryption_failed` | wrong password or a damaged link; the view was used |

```python
try:
    voidnote.create("x")
except voidnote.VoidNoteError as e:
    if e.status == 429:
        print(f"rate limited, retry in {e.retry_after}s: {e}")
```

### Void Streams

Live encrypted real-time channels. Creating one needs an API key from a free account; watching doesn't.

```python
import voidnote

# Create a channel
stream = voidnote.create_stream(api_key="vn_...", title="Deploy #42")
print(stream.url)  # share this URL with watchers

# Write messages (write and close are authenticated with the same API key)
stream.write("Starting deployment...")
stream.write("Build complete.")
stream.close()  # self-destructs all content

# Watch a stream: yields decrypted messages as they arrive
for message in voidnote.watch(stream.url):
    print(message)

# Password-protected stream
for message in voidnote.watch(url, password="hunter2"):
    print(message)
```

## Security model

```
server generates  tokenId  (32-char hex, stored as lookup key)
client generates  secret   (32-char hex, NEVER sent to server)

key        = SHA-256(bytes.fromhex(secret))                                kdf "sha256"
key        = PBKDF2-HMAC-SHA256(password, bytes.fromhex(secret), 600000)   kdf "pbkdf2-sha256-600k"
ciphertext = AES-256-GCM(plaintext, key, random_12_byte_iv)
share URL  = https://voidnote.net/n/{tokenId}#{secret}
```

The `#fragment` is never transmitted to HTTP servers per spec. The server has ciphertext; you have the key.

## Requirements

- Python 3.9+
- `cryptography >= 41.0.0` (installed automatically)

## Tests

```bash
uv run --no-project --with pytest --with cryptography --with-editable . python -m pytest tests   # mocked network
uv run --no-project --with cryptography --with-editable . python tests/live.py                # real notes on voidnote.net
```

## Links

- [voidnote.net](https://voidnote.net)
- [API reference](https://voidnote.net/docs)
- [CLI reference](https://voidnote.net/cli)
- [GitHub](https://github.com/quantum-encoding/voidnote-python)
