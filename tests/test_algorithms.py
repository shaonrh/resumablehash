import hashlib
import pickle
import random

import pytest
import resumablehash

ALGORITHMS = [
    ("sha256", 32, 64),
    ("sha384", 48, 128),
    ("sha512", 64, 128),
]


@pytest.fixture(params=ALGORITHMS, ids=[a[0] for a in ALGORITHMS])
def algo_info(request):
    name, digest_size, block_size = request.param
    cls = getattr(resumablehash, name)
    return name, cls, digest_size, block_size


class TestAlgorithms:
    def test_basic_hash(self, algo_info):
        name, cls, _, _ = algo_info
        h1 = cls(b"hello world")
        h2 = hashlib.new(name, b"hello world")
        assert h1.digest() == h2.digest()
        assert h1.hexdigest() == h2.hexdigest()

    def test_constructor_with_data(self, algo_info):
        _, cls, _, _ = algo_info
        h1 = cls(b"test data")
        h2 = cls()
        h2.update(b"test data")
        assert h1.hexdigest() == h2.hexdigest()

    def test_hexdigest_length(self, algo_info):
        _, cls, digest_size, _ = algo_info
        h = cls(b"hello world")
        assert len(h.hexdigest()) == digest_size * 2

    def test_digest_length(self, algo_info):
        _, cls, digest_size, _ = algo_info
        h = cls(b"hello world")
        assert len(h.digest()) == digest_size

    def test_properties(self, algo_info):
        name, cls, digest_size, block_size = algo_info
        h = cls()
        assert h.digest_size == digest_size
        assert h.block_size == block_size
        assert h.name == name

    def test_copy_independence(self, algo_info):
        _, cls, _, _ = algo_info
        h1 = cls(b"hello")
        h2 = h1.copy()
        assert h1.hexdigest() == h2.hexdigest()
        assert h1.__getstate__() == h2.__getstate__()
        h1.update(b" world")
        h2.update(b" there")
        assert h1.hexdigest() != h2.hexdigest()

    def test_pickle_roundtrip(self, algo_info):
        _, cls, _, _ = algo_info
        h = cls(b"hello world")
        state = pickle.dumps(h)
        h2 = pickle.loads(state)
        assert h.hexdigest() == h2.hexdigest()

    def test_type_error_on_string(self, algo_info):
        _, cls, _, _ = algo_info
        with pytest.raises(TypeError):
            cls("not bytes")

    def test_empty_input(self, algo_info):
        name, cls, _, _ = algo_info
        h1 = cls(b"")
        h2 = hashlib.new(name, b"")
        assert h1.hexdigest() == h2.hexdigest()

    def test_empty_update(self, algo_info):
        _, cls, _, _ = algo_info
        h1 = cls(b"data")
        h2 = cls(b"data")
        h2.update(b"")
        assert h1.hexdigest() == h2.hexdigest()

    def test_random_cross_validation(self, algo_info):
        name, cls, _, _ = algo_info
        h1 = cls()
        h2 = hashlib.new(name)
        rng = random.Random(42)
        for _ in range(200):
            chunk = bytes([rng.randint(0, 255)] * rng.randint(1, 1000))
            h1.update(chunk)
            h2.update(chunk)
            assert h1.digest() == h2.digest()
            assert h1.hexdigest() == h2.hexdigest()
            h1 = pickle.loads(pickle.dumps(h1))

    def test_block_boundary_sizes(self, algo_info):
        name, cls, _, block_size = algo_info
        sizes = [0, 1, block_size - 1, block_size, block_size + 1,
                 block_size * 2 - 1, block_size * 2, block_size * 2 + 1,
                 1024]
        for size in sizes:
            data = bytes(range(256)) * (size // 256 + 1)
            data = data[:size]
            h1 = cls(data)
            h2 = hashlib.new(name, data)
            assert h1.hexdigest() == h2.hexdigest(), f"Mismatch at size={size}"

    def test_update_rejects_string(self, algo_info):
        _, cls, _, _ = algo_info
        h = cls(b"")
        with pytest.raises(TypeError):
            h.update("hello")

    def test_update_accepts_bytearray(self, algo_info):
        _, cls, _, _ = algo_info
        h1 = cls()
        h1.update(bytearray(b"hello"))
        h2 = cls(b"hello")
        assert h1.hexdigest() == h2.hexdigest()

    def test_new_factory(self, algo_info):
        name, cls, _, _ = algo_info
        h1 = resumablehash.new(name, b"hello")
        h2 = cls(b"hello")
        assert h1.hexdigest() == h2.hexdigest()

    def test_new_factory_no_data(self, algo_info):
        """new(name) with no data arg must match empty constructor."""
        name, cls, _, _ = algo_info
        h1 = resumablehash.new(name)
        h2 = cls()
        assert h1.hexdigest() == h2.hexdigest()

    def test_new_factory_empty_bytes(self, algo_info):
        """new(name, b'') must not silently discard the argument (Issue 4 regression)."""
        name, cls, _, _ = algo_info
        h1 = resumablehash.new(name, b"")
        h2 = cls(b"")
        assert h1.hexdigest() == h2.hexdigest()

    def test_new_factory_invalid_name(self, algo_info):
        """new() with an unsupported algorithm must raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            resumablehash.new("md5")

    def test_direct_import(self, algo_info):
        name, cls, _, _ = algo_info
        h = cls(b"hello world")
        assert h.hexdigest() == hashlib.new(name, b"hello world").hexdigest()

    def test_large_input(self, algo_info):
        name, cls, _, _ = algo_info
        data = b"x" * (1024 * 1024)
        h1 = cls(data)
        h2 = hashlib.new(name, data)
        assert h1.hexdigest() == h2.hexdigest()

    # Issue 11: memoryview test coverage
    def test_update_accepts_memoryview(self, algo_info):
        """update() must accept memoryview input."""
        name, cls, _, _ = algo_info
        data = b"hello world"
        h1 = cls()
        h1.update(memoryview(data))
        h2 = hashlib.new(name, data)
        assert h1.hexdigest() == h2.hexdigest()

    def test_constructor_accepts_memoryview(self, algo_info):
        """Constructor must accept memoryview input (after Issue 3 fix)."""
        name, cls, _, _ = algo_info
        data = b"hello world"
        h1 = cls(memoryview(data))
        h2 = hashlib.new(name, data)
        assert h1.hexdigest() == h2.hexdigest()

    def test_constructor_accepts_bytearray(self, algo_info):
        """Constructor must accept bytearray input (after Issue 3 fix)."""
        name, cls, _, _ = algo_info
        data = b"hello world"
        h1 = cls(bytearray(data))
        h2 = hashlib.new(name, data)
        assert h1.hexdigest() == h2.hexdigest()

    def test_update_accepts_memoryview_slice(self, algo_info):
        """update() must handle memoryview slices correctly."""
        name, cls, _, _ = algo_info
        data = b"XXhello worldXX"
        mv = memoryview(data)[2:-2]  # slice out "hello world"
        h1 = cls()
        h1.update(mv)
        h2 = hashlib.new(name, b"hello world")
        assert h1.hexdigest() == h2.hexdigest()

    # Issue 13: concurrent access test
    def test_concurrent_independent_hashing(self, algo_info):
        """Independent hash objects in separate threads must not interfere."""
        import concurrent.futures

        name, cls, _, _ = algo_info

        def hash_data(seed):
            rng = random.Random(seed)
            data = bytes(rng.getrandbits(8) for _ in range(10000))
            h = cls()
            # Feed in small chunks
            for i in range(0, len(data), 100):
                h.update(data[i:i+100])
            return h.hexdigest(), hashlib.new(name, data).hexdigest()

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(hash_data, seed) for seed in range(20)]
            for f in concurrent.futures.as_completed(futures):
                got, expected = f.result()
                assert got == expected
