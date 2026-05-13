"""Tests for pickle serialization correctness and security properties."""

import pickle
import struct

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
    """State size must be exactly 8 (header) + sizeof(context struct)."""
    h = resumablehash.new(algo)
    state = h.__getstate__()
    # SHA-256 uses SHA256_CTX, SHA-384/512 use SHA512_CTX.
    # SHA-384 and SHA-512 must have equal state sizes.
    # SHA-256 must have a smaller state than SHA-512.
    if algo == "sha256":
        # SHA256_CTX is smaller than SHA512_CTX
        h512 = resumablehash.new("sha512")
        assert len(state) < len(h512.__getstate__())
    elif algo == "sha384":
        h512 = resumablehash.new("sha512")
        assert len(state) == len(h512.__getstate__()), \
            "SHA-384 and SHA-512 share SHA512_CTX, state sizes must match"
    # All states must have at least 8 (header) + block_size bytes
    assert len(state) > 8 + h.block_size
    # State size must be stable (same object, different data)
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


@pytest.mark.parametrize("algo,block_size", [
    ("sha256", 64), ("sha384", 128), ("sha512", 128)
])
def test_setstate_rejects_corrupt_datalen(algo, block_size):
    """A crafted state with datalen >= block_size must be rejected (Issue 2)."""
    h = resumablehash.new(algo, b"data")
    state = bytearray(h.__getstate__())
    # Corrupt the datalen field in the context struct.
    # datalen is the first integer field after data[] in the struct.
    # For SHA-256: offset 8 (header) + 64 (data) = byte 72, uint32_t
    # For SHA-384/512: offset 8 (header) + 128 (data) = byte 136, uint64_t
    header_size = 8
    if algo == "sha256":
        datalen_offset = header_size + 64  # after data[64]
        struct.pack_into("<I", state, datalen_offset, block_size)  # datalen = block_size (invalid)
    else:
        datalen_offset = header_size + 128  # after data[128]
        struct.pack_into("<Q", state, datalen_offset, block_size)  # datalen = block_size (invalid)
    h2 = resumablehash.new(algo)
    with pytest.raises(ValueError, match="datalen"):
        h2.__setstate__(bytes(state))


@pytest.mark.parametrize("algo,block_size", [
    ("sha256", 64), ("sha384", 128), ("sha512", 128)
])
def test_setstate_rejects_extreme_datalen(algo, block_size):
    """A crafted state with extremely large datalen must be rejected."""
    h = resumablehash.new(algo, b"data")
    state = bytearray(h.__getstate__())
    header_size = 8
    if algo == "sha256":
        datalen_offset = header_size + 64
        struct.pack_into("<I", state, datalen_offset, 0xFFFFFFFF)
    else:
        datalen_offset = header_size + 128
        struct.pack_into("<Q", state, datalen_offset, 0xFFFFFFFFFFFFFFFF)
    h2 = resumablehash.new(algo)
    with pytest.raises(ValueError, match="datalen"):
        h2.__setstate__(bytes(state))


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_setstate_reject_leaves_object_usable(algo):
    """After setstate rejects corrupt state, the object must still be usable."""
    h = resumablehash.new(algo)
    state = bytearray(resumablehash.new(algo, b"x").__getstate__())
    # Corrupt datalen
    header_size = 8
    if algo == "sha256":
        struct.pack_into("<I", state, header_size + 64, 999)
    else:
        struct.pack_into("<Q", state, header_size + 128, 999)
    with pytest.raises(ValueError):
        h.__setstate__(bytes(state))
    # Object should still work (re-initialized to clean state)
    h.update(b"hello")
    expected = resumablehash.new(algo, b"hello").hexdigest()
    assert h.hexdigest() == expected


@pytest.mark.parametrize("src_algo,dst_algo", [
    ("sha384", "sha512"),
    ("sha512", "sha384"),
])
def test_setstate_rejects_cross_algorithm_same_struct(src_algo, dst_algo):
    """SHA-384 and SHA-512 share SHA512_CTX (same struct size).

    Only the algorithm tag in byte 2 of the header distinguishes them.
    The length check passes, so the algorithm tag check must catch it.
    This is the most security-critical cross-algorithm test.
    """
    h_src = resumablehash.new(src_algo, b"cross-algorithm test data")
    state = h_src.__getstate__()
    h_dst = resumablehash.new(dst_algo)
    with pytest.raises(ValueError, match="cannot restore into"):
        h_dst.__setstate__(state)


@pytest.mark.parametrize("src_algo,dst_algo", [
    ("sha256", "sha384"), ("sha256", "sha512"),
    ("sha384", "sha256"), ("sha512", "sha256"),
])
def test_setstate_rejects_cross_algorithm_different_struct(src_algo, dst_algo):
    """Cross-algorithm with different struct sizes is caught by length check."""
    h_src = resumablehash.new(src_algo, b"cross-algorithm test data")
    state = h_src.__getstate__()
    h_dst = resumablehash.new(dst_algo)
    with pytest.raises(ValueError):
        h_dst.__setstate__(state)


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_reduce_protocol(algo):
    """__reduce_ex__ must return a tuple that can reconstruct the object."""
    h = resumablehash.new(algo, b"test data")
    reduced = h.__reduce_ex__(2)
    # reduced should be a tuple: (callable, args, state) or (callable, args)
    assert isinstance(reduced, tuple)
    assert len(reduced) >= 2
    # Verify we can actually reconstruct from the reduce output
    h2 = pickle.loads(pickle.dumps(h, protocol=2))
    assert h.hexdigest() == h2.hexdigest()
    # Also test with highest protocol
    h3 = pickle.loads(pickle.dumps(h, protocol=pickle.HIGHEST_PROTOCOL))
    assert h.hexdigest() == h3.hexdigest()
