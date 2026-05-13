import hashlib
import pickle
import random

import pytest
import resumablehash


class TestSHA256:
    def test_basic_hash(self):
        h1 = resumablehash.sha256(b"hello world")
        h2 = hashlib.sha256(b"hello world")
        assert h1.digest() == h2.digest()
        assert h1.hexdigest() == h2.hexdigest()

    def test_constructor_with_data(self):
        h1 = resumablehash.sha256(b"test data")
        h2 = resumablehash.sha256()
        h2.update(b"test data")
        assert h1.hexdigest() == h2.hexdigest()

    def test_hexdigest_length(self):
        h = resumablehash.sha256(b"hello world")
        assert len(h.hexdigest()) == 64

    def test_digest_length(self):
        h = resumablehash.sha256(b"hello world")
        assert len(h.digest()) == 32

    def test_properties(self):
        h = resumablehash.sha256()
        assert h.digest_size == 32
        assert h.block_size == 64
        assert h.name == "sha256"

    def test_copy_independence(self):
        h1 = resumablehash.sha256(b"hello")
        h2 = h1.copy()
        assert h1.hexdigest() == h2.hexdigest()
        assert h1.__getstate__() == h2.__getstate__()
        h1.update(b" world")
        h2.update(b" there")
        assert h1.hexdigest() != h2.hexdigest()

    def test_pickle_roundtrip(self):
        h = resumablehash.sha256(b"hello world")
        state = pickle.dumps(h)
        h2 = pickle.loads(state)
        assert h.hexdigest() == h2.hexdigest()

    def test_type_error_on_string(self):
        with pytest.raises(TypeError):
            resumablehash.sha256("not bytes")

    def test_empty_input(self):
        h1 = resumablehash.sha256(b"")
        h2 = hashlib.sha256(b"")
        assert h1.hexdigest() == h2.hexdigest()

    def test_empty_update(self):
        h1 = resumablehash.sha256(b"data")
        h2 = resumablehash.sha256(b"data")
        h2.update(b"")
        assert h1.hexdigest() == h2.hexdigest()

    def test_random_cross_validation(self):
        """200 random chunks with pickle roundtrip each iteration."""
        h1 = resumablehash.sha256()
        h2 = hashlib.sha256()
        rng = random.Random(42)
        for _ in range(200):
            chunk = bytes([rng.randint(0, 255)] * rng.randint(1, 1000))
            h1.update(chunk)
            h2.update(chunk)
            assert h1.digest() == h2.digest()
            assert h1.hexdigest() == h2.hexdigest()
            h1 = pickle.loads(pickle.dumps(h1))

    def test_block_boundary_sizes(self):
        for size in [0, 1, 63, 64, 65, 127, 128, 129, 256, 1024]:
            data = bytes(range(256)) * (size // 256 + 1)
            data = data[:size]
            h1 = resumablehash.sha256(data)
            h2 = hashlib.sha256(data)
            assert h1.hexdigest() == h2.hexdigest(), f"Mismatch at size={size}"

    def test_new_factory(self):
        h1 = resumablehash.new("sha256", b"hello")
        h2 = resumablehash.sha256(b"hello")
        assert h1.hexdigest() == h2.hexdigest()

    def test_update_rejects_string(self):
        """update() must reject str input with TypeError (H1 fix)."""
        h = resumablehash.sha256(b"")
        with pytest.raises(TypeError):
            h.update("hello")

    def test_update_accepts_bytearray(self):
        """update() must accept bytearray (same digest as bytes)."""
        h1 = resumablehash.sha256(b"")
        h1.update(bytearray(b"hello"))
        h2 = resumablehash.sha256(b"hello")
        assert h1.hexdigest() == h2.hexdigest()

    def test_direct_import(self):
        from resumablehash import sha256

        h = sha256(b"hello world")
        assert h.hexdigest() == hashlib.sha256(b"hello world").hexdigest()
