from ._hash_ext import sha256, sha384, sha512

_algorithms = {"sha256": sha256, "sha384": sha384, "sha512": sha512}


def new(name, data=b""):
    if name not in _algorithms:
        raise ValueError(f"Unsupported algorithm: {name}")
    return _algorithms[name](data) if data else _algorithms[name]()
