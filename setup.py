from setuptools import setup, find_packages, Extension


setup(
    name="resumablehash",
    version="1.0.0",  # canonical version is in pyproject.toml
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=False,
    ext_modules=[Extension(
        "resumablehash._hash_ext",
        [
            "src_ext/_hash_ext.c",
            "src_ext/sha256.c",
            "src_ext/sha512.c",
        ],
        include_dirs=["src_ext"],
    )
    ]
)
