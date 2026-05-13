"""Tests for cross-algorithm state isolation."""

import pytest
import resumablehash


def test_sha256_state_rejected_by_sha512():
    """SHA-256 state must not load into SHA-512 (different struct size)."""
    h256 = resumablehash.sha256(b"data")
    state = h256.__getstate__()
    h512 = resumablehash.sha512()
    with pytest.raises(ValueError, match="Invalid state length"):
        h512.__setstate__(state)


def test_sha512_state_rejected_by_sha256():
    """SHA-512 state must not load into SHA-256 (different struct size)."""
    h512 = resumablehash.sha512(b"data")
    state = h512.__getstate__()
    h256 = resumablehash.sha256()
    with pytest.raises(ValueError, match="Invalid state length"):
        h256.__setstate__(state)


def test_sha384_state_rejected_by_sha256():
    """SHA-384 state must not load into SHA-256 (different struct size)."""
    h384 = resumablehash.sha384(b"data")
    state = h384.__getstate__()
    h256 = resumablehash.sha256()
    with pytest.raises(ValueError, match="Invalid state length"):
        h256.__setstate__(state)


def test_sha256_state_rejected_by_sha384():
    """SHA-256 state must not load into SHA-384 (different struct size)."""
    h256 = resumablehash.sha256(b"data")
    state = h256.__getstate__()
    h384 = resumablehash.sha384()
    with pytest.raises(ValueError, match="Invalid state length"):
        h384.__setstate__(state)


def test_sha384_state_rejected_by_sha512():
    """SHA-384 state cannot be loaded into SHA-512 (algorithm tag mismatch)."""
    h384 = resumablehash.sha384(b"test")
    state = h384.__getstate__()
    h512 = resumablehash.sha512()
    with pytest.raises(ValueError, match="sha384.*sha512"):
        h512.__setstate__(state)


def test_sha512_state_rejected_by_sha384():
    """SHA-512 state cannot be loaded into SHA-384 (algorithm tag mismatch)."""
    h512 = resumablehash.sha512(b"test")
    state = h512.__getstate__()
    h384 = resumablehash.sha384()
    with pytest.raises(ValueError, match="sha512.*sha384"):
        h384.__setstate__(state)


def test_new_factory_rejects_unknown():
    with pytest.raises(ValueError, match="Unsupported"):
        resumablehash.new("md5")


def test_new_factory_rejects_unknown_algorithms():
    for name in ["blake2b", "sha3_256", "sha1", "md5", ""]:
        with pytest.raises(ValueError):
            resumablehash.new(name)


def test_all_algorithms_produce_different_digests():
    """Same input through different algorithms must produce different digests."""
    data = b"hello world"
    digests = set()
    for algo in ["sha256", "sha384", "sha512"]:
        h = resumablehash.new(algo, data)
        digests.add(h.hexdigest())
    assert len(digests) == 3
