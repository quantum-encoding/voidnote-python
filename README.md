# voidnote

Official Python SDK for [VoidNote](https://voidnote.net) — zero-knowledge self-destructing notes.

## Install

```bash
pip install voidnote
```

## Usage

### Read a note

```python
import voidnote

result = voidnote.read("https://voidnote.net/note/abc123...")
print(result.content)   # decrypted content
print(result.destroyed) # True if view limit was reached
```

### Create a note (requires API key)

```python
import voidnote

result = voidnote.create(
    "my secret value",
    api_key="vn_...",
    max_views=1,
    title="Deploy key",
)
print(result.url)  # share this link
```

## Requirements

- Python 3.9+
- `cryptography >= 41.0.0`

## Links

- [voidnote.net](https://voidnote.net)
- [How it works](https://voidnote.net/how-it-works)
- [GitHub](https://github.com/quantum-encoding/voidnote-python)
