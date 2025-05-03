import setuptools

setuptools.setup(
    name="bitwarden-secrets-manager-python",
    version="0.1.0",
    author="Björn",
    author_email="bws-python@schrammel.dev",
    description="A Python package for Bitwarden Secrets Manager.",
    long_description_content_type="text/markdown",
    url="",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests",
        "urllib3",
        "rich",
        "pydantic",
        "httpx",
        "tqdm",
        "pycryptodome",
        "cryptography"
    ],
    include_package_data=True
)