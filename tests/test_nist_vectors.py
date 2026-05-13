"""
NIST FIPS 180-4 test vector validation for all SHA-2 algorithms.

Vectors sourced from:
  - FIPS 180-4: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
  - NIST CSRC: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
"""

import pytest
import resumablehash


NIST_VECTORS = {
    "sha256": [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
        (
            b"a" * 1000000,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
    ],
    "sha384": [
        (
            b"",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
            "274edebfe76f65fbd51ad2f14898b95b",
        ),
        (
            b"abc",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
            "fcc7c71a557e2db966c3e9fa91746039",
        ),
        (
            b"a" * 1000000,
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
            "07b8b3dc38ecc4ebae97ddd87f3d8985",
        ),
    ],
    "sha512": [
        (
            b"",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            b"abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
        (
            b"a" * 1000000,
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
            "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        ),
    ],
}


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_nist_vectors_oneshot(algo):
    """Each NIST vector hashed in one shot must produce the expected digest."""
    for input_bytes, expected in NIST_VECTORS[algo]:
        h = resumablehash.new(algo, input_bytes)
        assert h.hexdigest() == expected, (
            f"{algo}: failed for input len={len(input_bytes)}"
        )


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_nist_vectors_byte_at_a_time(algo):
    """Hash NIST inputs one byte at a time to verify update() boundary handling."""
    for input_bytes, expected in NIST_VECTORS[algo]:
        if len(input_bytes) > 10000:
            continue
        h = resumablehash.new(algo)
        for b in input_bytes:
            h.update(bytes([b]))
        assert h.hexdigest() == expected, (
            f"{algo}: byte-at-a-time failed for input len={len(input_bytes)}"
        )


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_nist_vectors_digest_bytes(algo):
    """Verify digest() returns correct raw bytes matching the hex vectors."""
    for input_bytes, expected_hex in NIST_VECTORS[algo]:
        h = resumablehash.new(algo, input_bytes)
        assert h.digest() == bytes.fromhex(expected_hex)


@pytest.mark.parametrize("algo", ["sha256", "sha384", "sha512"])
def test_nist_million_a_chunked(algo):
    """Hash 1 million 'a' characters in 10KB chunks."""
    expected = NIST_VECTORS[algo][-1][1]
    h = resumablehash.new(algo)
    chunk = b"a" * 10000
    for _ in range(100):
        h.update(chunk)
    assert h.hexdigest() == expected
