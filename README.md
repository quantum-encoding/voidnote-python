# voidnote

Official Python SDK for [VoidNote](https://voidnote.net) — zero-knowledge self-destructing notes and live encrypted streams.

**v0.4.1** · Python 3.9+ · zero-knowledge v1 API

## Install

```bash
pip install voidnote
```

## Quick start

```python
import voidnote

# Create a note — content is encrypted locally, server never sees plaintext
result = voidnote.create(
    "my secret value",
    api_key="vn_...",
    max_views=1,       # destroy after this many reads (1–100)
    expires_in=1,      # hours until expiry (1–720)
)
print(result.url)    # https://voidnote.net/n/<tokenId>#<secret>
print(result.token)  # 32-char tokenId
```

## API

### `voidnote.create(content, *, api_key, max_views=1, expires_in=1) → CreateResult`

Encrypt `content` locally and store the ciphertext. Requires an API key from your [dashboard](https://voidnote.net/dashboard).

```python
result = voidnote.create("deploy key: abc123", api_key="vn_...", max_views=3)
print(result.url)        # full shareable URL — includes #secret
print(result.token)      # 32-char tokenId only
print(result.expires_at)
```

### `voidnote.read(url) → ReadResult`

Fetch and decrypt a note. Consumes one view. Accepts both v1 URLs (`/n/<token>#<secret>`) and legacy URLs.

```python
note = voidnote.read("https://voidnote.net/n/<tokenId>#<secret>")
print(note.content)         # decrypted plaintext
print(note.views_remaining) # views left after this read
print(note.destroyed)       # True if this was the last view
```

### `voidnote.peek(url) → PeekResult`

Check metadata without consuming a view.

```python
meta = voidnote.peek("https://voidnote.net/n/<tokenId>#<secret>")
print(meta.exists)
print(meta.views_remaining)
print(meta.expires_at)
```

### Void Streams

Live encrypted real-time channels. Messages are encrypted before leaving your machine.

```python
import voidnote

# Create a channel
stream = voidnote.create_stream(api_key="vn_...", title="Deploy #42")
print(stream.url)  # share this URL with watchers

# Write messages (write and close are authenticated with the same API key)
stream.write("Starting deployment...")
stream.write("Build complete.")
stream.close()  # self-destructs all content

# Watch a stream — yields decrypted messages as they arrive
for message in voidnote.watch(stream.url):
    print(message)

# Password-protected stream
for message in voidnote.watch(url, password="hunter2"):
    print(message)
```

### Crypto payments

```python
# Create a payment order
order = voidnote.create_crypto_order(
    api_key="vn_...",
    bundle_id="starter",   # "test" | "starter" | "standard" | "pro"
    chain="polygon",
    token="USDT",
)
print(f"Send {order.amount} {order.token} to {order.to_address}")

# After sending, submit the tx hash
result = voidnote.submit_crypto_payment(
    api_key="vn_...",
    order_id=order.order_id,
    tx_hash="0x...",
)
print(f"+{result.credits_added} credits, balance: {result.credits}")
```

## Security model

```
server generates  tokenId  (32-char hex — stored as lookup key)
client generates  secret   (32-char hex — NEVER sent to server)

key        = SHA-256(bytes.fromhex(secret))
ciphertext = AES-256-GCM(plaintext, key, random_12_byte_iv)
share URL  = https://voidnote.net/n/{tokenId}#{secret}
```

The `#fragment` is never transmitted to HTTP servers per spec. The server has ciphertext; you have the key.

## Requirements

- Python 3.9+
- `cryptography >= 41.0.0` (installed automatically)

## Links

- [voidnote.net](https://voidnote.net)
- [API reference](https://voidnote.net/docs)
- [CLI reference](https://voidnote.net/cli)
- [GitHub](https://github.com/quantum-encoding/voidnote-python)
