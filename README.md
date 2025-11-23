# TezCrypto

TezCrypto is a fast and portable cryptography library for Python, written in Rust. It is a migration of the original TgCrypto library.

## Features

- AES-256-CBC
- AES-256-CTR
- AES-256-IGE

## Installation

```bash
pip install tezcrypto
```

## Usage

```python
import tezcrypto
import os

key = os.urandom(32)
iv = os.urandom(32)
data = os.urandom(64)

# IGE Mode
encrypted = tezcrypto.ige256_encrypt(data, key, iv)
decrypted = tezcrypto.ige256_decrypt(encrypted, key, iv)
assert data == decrypted

# CTR Mode
iv_ctr = os.urandom(16)
state = bytes(1) # Initial state
encrypted_ctr = tezcrypto.ctr256_encrypt(data, key, iv_ctr, state)
decrypted_ctr = tezcrypto.ctr256_decrypt(encrypted_ctr, key, iv_ctr, state)
assert data == decrypted_ctr

# CBC Mode
iv_cbc = os.urandom(16)
encrypted_cbc = tezcrypto.cbc256_encrypt(data, key, iv_cbc)
decrypted_cbc = tezcrypto.cbc256_decrypt(encrypted_cbc, key, iv_cbc)
assert data == decrypted_cbc
```

## Development

To build and install locally:

```bash
# Install maturin
pip install maturin

# Build and install
maturin develop --features python
```

## Testing

```bash
# Run Rust tests
cargo test

# Run Python validation
python validate.py
```

## License

LGPL-3.0

maturin develop
```
