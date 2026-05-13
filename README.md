# resumablehash

Resumable SHA-2 hash implementations (SHA-256, SHA-384, SHA-512) with pickle support. Hash state can be saved and restored between sessions, enabling chunked hashing across multiple HTTP requests or processes.

Uses a parameterized C implementation for all three algorithms — one template generates SHA-256, SHA-384, and SHA-512 with different constants and word sizes.

## Installation

```bash
pip install resumablehash
```

## Usage

### Direct constructors

```python
import resumablehash

h = resumablehash.sha256(b"initial data")
h = resumablehash.sha384()
h = resumablehash.sha512()
```

### Factory function

```python
h = resumablehash.new("sha512")
h = resumablehash.new("sha256", b"initial data")
```

### Resumable hashing with pickle

```python
import pickle
import resumablehash

# Start hashing
hasher = resumablehash.sha512()
hasher.update(b"first chunk of data")

# Save state (e.g. to database between HTTP requests)
saved = pickle.dumps(hasher)

# Restore and continue
restored = pickle.loads(saved)
restored.update(b"second chunk")
print(restored.hexdigest())
```

### API

All hash objects provide the same interface:

```python
h.update(data)      # Feed bytes into the hash
h.digest()          # Return raw bytes digest
h.hexdigest()       # Return hex string digest
h.copy()            # Return independent copy
h.digest_size       # 32 (SHA-256), 48 (SHA-384), or 64 (SHA-512)
h.block_size        # 64 (SHA-256) or 128 (SHA-384/512)
h.name              # "sha256", "sha384", or "sha512"
pickle.dumps(h)     # Serialize via __getstate__/__setstate__
```

## Performance

The C implementation is approximately 2.5x slower than `hashlib` (which uses hardware-accelerated OpenSSL). State serialization is near-instant (~1 us for a `memcpy` of ~100-200 bytes).

| Algorithm | resumablehash | hashlib (OpenSSL) |
|-----------|--------------|-------------------|
| SHA-256   | ~400 MB/s    | ~1 GB/s           |
| SHA-512   | ~320 MB/s    | ~800 MB/s         |

In practice, the bottleneck is network and storage I/O, not hashing speed.

## Development

### Running tests

```bash
pip install -e ".[test]"
pytest tests/ -v --tb=short -m "not benchmark"
```

### Releasing

1. Update the version in both `pyproject.toml` and `setup.py`.
2. Commit: `git commit -am "release: vX.Y.Z"`
3. Tag: `git tag -a vX.Y.Z -m "vX.Y.Z: description"`
4. Push: `git push origin devel --tags`

Pushing a `v*` tag triggers the release workflow, which builds a wheel and sdist on UBI 9 / Python 3.12, runs the full test suite, and creates a GitHub Release with the artifacts attached.

## Acknowledgements

- Brad Conte for the public domain SHA-256 C implementation ([crypto-algorithms](https://github.com/B-Con/crypto-algorithms))
- Luke Moore for the original [resumablesha256](https://github.com/luke-moore/resumablesha256) library
- SHA-512 round constants and initial values from [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
