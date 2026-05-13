"""Tests for pickle serialization correctness and security properties."""

import pickle

import pytest
import resumablehash


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_pickle_module_name(algo):
    """Pickle data must reference 'resumablehash' module."""
    h = resumablehash.new(algo, b"data")
    data = pickle.dumps(h)
    assert b"resumablehash" in data


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_getstate_returns_bytes(algo):
    h = resumablehash.new(algo, b"data")
    state = h.__getstate__()
    assert isinstance(state, bytes)


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_getstate_size(algo):
    """State size should match the context struct size."""
    h = resumablehash.new(algo)
    state = h.__getstate__()
    if algo == "sha256":
        assert len(state) > 0
    else:
        assert len(state) > 0
    h_with_data = resumablehash.new(algo, b"some data here")
    assert len(h_with_data.__getstate__()) == len(state)


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_setstate_rejects_too_short(algo):
    h = resumablehash.new(algo)
    with pytest.raises(ValueError, match="Invalid state length"):
        h.__setstate__(b"too short")


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_setstate_rejects_too_long(algo):
    h = resumablehash.new(algo)
    with pytest.raises(ValueError, match="Invalid state length"):
        h.__setstate__(b"\x00" * 1024)


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_setstate_rejects_non_bytes(algo):
    h = resumablehash.new(algo)
    with pytest.raises(TypeError):
        h.__setstate__("not bytes")


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_pickle_preserves_state_exactly(algo):
    """Pickle roundtrip must produce byte-identical state."""
    h1 = resumablehash.new(algo, b"test data")
    state_before = h1.__getstate__()
    h2 = pickle.loads(pickle.dumps(h1))
    state_after = h2.__getstate__()
    assert state_before == state_after


def test_sha256_sha512_state_sizes_differ():
    """SHA-256 and SHA-512 contexts have different sizes — fundamental safety check."""
    h256 = resumablehash.sha256()
    h512 = resumablehash.sha512()
    assert len(h256.__getstate__()) != len(h512.__getstate__())


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_getstate_has_rh_header(algo):
    """__getstate__ output must start with the RH magic bytes."""
    h = resumablehash.new(algo, b"data")
    state = h.__getstate__()
    assert state[0:2] == b"RH", "Missing RH magic header"


@pytest.mark.parametrize("algo,expected_id", [
    ("sha256", 0x01), ("sha384", 0x02), ("sha512", 0x03)
])
def test_getstate_algorithm_tag(algo, expected_id):
    """__getstate__ must encode the correct algorithm ID in byte 2."""
    h = resumablehash.new(algo, b"test")
    state = h.__getstate__()
    assert state[2] == expected_id


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_getstate_version_byte(algo):
    """__getstate__ must encode version 0x01 in byte 3."""
    h = resumablehash.new(algo, b"test")
    state = h.__getstate__()
    assert state[3] == 0x01


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_setstate_rejects_untagged_raw_state(algo):
    """Raw context bytes without the 8-byte header must be rejected (AC-10)."""
    h = resumablehash.new(algo, b"data")
    # Get tagged state and strip the 8-byte header to get raw context
    tagged_state = h.__getstate__()
    raw_ctx = tagged_state[8:]
    h2 = resumablehash.new(algo)
    with pytest.raises(ValueError):
        h2.__setstate__(raw_ctx)


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_setstate_rejects_correct_length_wrong_magic(algo):
    """A buffer of the correct tagged length but wrong magic must be rejected."""
    h = resumablehash.new(algo, b"data")
    tagged_state = h.__getstate__()
    # Create a zero-filled buffer of the same length (magic bytes 0x00 0x00)
    fake_state = b"\x00" * len(tagged_state)
    h2 = resumablehash.new(algo)
    with pytest.raises(ValueError, match="missing resumablehash header"):
        h2.__setstate__(fake_state)


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_setstate_rejects_wrong_version(algo):
    """A buffer with correct magic but wrong version byte must be rejected."""
    h = resumablehash.new(algo, b"data")
    tagged_state = bytearray(h.__getstate__())
    tagged_state[3] = 0xFF  # corrupt version byte
    h2 = resumablehash.new(algo)
    with pytest.raises(ValueError, match="Unsupported state format version"):
        h2.__setstate__(bytes(tagged_state))
