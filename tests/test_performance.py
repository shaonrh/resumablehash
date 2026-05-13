"""Performance benchmarks comparing resumablehash vs hashlib.

Not run in CI by default — use: pytest tests/test_performance.py -m benchmark -v
"""

import hashlib
import time

import pytest
import resumablehash

pytestmark = pytest.mark.benchmark


@pytest.mark.parametrize("algo", ["sha256", "sha512"])
def test_throughput_comparison(algo):
    """Compare resumablehash vs hashlib throughput on 10MB of data."""
    data = b"x" * (10 * 1024 * 1024)

    start = time.perf_counter()
    h1 = resumablehash.new(algo, data)
    _ = h1.hexdigest()
    resumable_time = time.perf_counter() - start

    start = time.perf_counter()
    h2 = hashlib.new(algo, data)
    _ = h2.hexdigest()
    hashlib_time = time.perf_counter() - start

    ratio = resumable_time / hashlib_time if hashlib_time > 0 else float("inf")
    print(f"\n{algo}: resumablehash={resumable_time:.4f}s, hashlib={hashlib_time:.4f}s, ratio={ratio:.1f}x")
    # Fail if more than 50x slower than hashlib (hashlib uses hardware acceleration)
    # This is a generous ceiling to catch catastrophic regressions, not a tight bound.
    # hashlib uses OpenSSL's AES-NI/SHA-NI instructions, so our pure-C impl will be
    # significantly slower. 50x is a reasonable "something went very wrong" threshold.
    assert ratio < 50, (
        f"{algo}: resumablehash is {ratio:.1f}x slower than hashlib, "
        f"exceeds 50x ceiling"
    )


@pytest.mark.parametrize("algo", ["sha256", "sha512"])
def test_pickle_overhead(algo):
    """Measure pickle serialize/deserialize time."""
    import pickle

    h = resumablehash.new(algo, b"some initial data")

    iterations = 10000
    start = time.perf_counter()
    for _ in range(iterations):
        data = pickle.dumps(h)
        h = pickle.loads(data)
    total = time.perf_counter() - start

    per_op = total / iterations * 1e6
    print(f"\n{algo}: pickle roundtrip = {per_op:.1f} us/op ({iterations} iterations)")
