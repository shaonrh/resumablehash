"""Tests simulating Quay's chunked blob upload pattern: hash, pickle, restore, repeat."""

import hashlib
import os
import pickle

import pytest
import resumablehash


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_chunked_upload_simulation(algo):
    """Simulate Quay's chunked blob upload: hash chunks, pickle between each."""
    blob = os.urandom(1024 * 1024)
    chunk_size = 64 * 1024

    h = resumablehash.new(algo)
    for i in range(0, len(blob), chunk_size):
        chunk = blob[i : i + chunk_size]
        h.update(chunk)
        saved = pickle.dumps(h)
        h = pickle.loads(saved)

    expected = hashlib.new(algo, blob).hexdigest()
    assert h.hexdigest() == expected


@pytest.mark.parametrize(
    "algo,block_size", [("sha256", 64), ("sha384", 128), ("sha512", 128)]
)
def test_pickle_at_every_byte(algo, block_size):
    """Pickle/unpickle after every single byte for two full blocks."""
    data = os.urandom(block_size * 2)
    h = resumablehash.new(algo)
    for b in data:
        h.update(bytes([b]))
        h = pickle.loads(pickle.dumps(h))
    expected = hashlib.new(algo, data).hexdigest()
    assert h.hexdigest() == expected


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_pickle_before_any_data(algo):
    """Pickle an empty hasher, restore, then hash — should match one-shot."""
    h = resumablehash.new(algo)
    h = pickle.loads(pickle.dumps(h))
    h.update(b"hello world")
    expected = hashlib.new(algo, b"hello world").hexdigest()
    assert h.hexdigest() == expected


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_multiple_pickle_cycles(algo):
    """Multiple pickle roundtrips with no data between them."""
    h = resumablehash.new(algo, b"initial")
    for _ in range(10):
        h = pickle.loads(pickle.dumps(h))
    expected = hashlib.new(algo, b"initial").hexdigest()
    assert h.hexdigest() == expected


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_variable_chunk_sizes(algo):
    """Hash with random chunk sizes, pickle between some chunks."""
    import random

    rng = random.Random(123)
    total_data = os.urandom(100000)
    h = resumablehash.new(algo)

    offset = 0
    while offset < len(total_data):
        chunk_size = rng.randint(1, 5000)
        chunk = total_data[offset : offset + chunk_size]
        h.update(chunk)
        offset += chunk_size
        if rng.random() < 0.3:
            h = pickle.loads(pickle.dumps(h))

    expected = hashlib.new(algo, total_data).hexdigest()
    assert h.hexdigest() == expected
