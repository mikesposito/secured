# secured

[![Crates.io][crates-badge]][crates-url]
![Build and test][build-status-url]
[![MIT licensed][mit-badge]][mit-url]
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/mikesposito/secured/issues)

[crates-badge]: https://img.shields.io/crates/v/secured.svg
[crates-url]: https://crates.io/crates/secured
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/mikesposito/secured/blob/main/LICENSE
[build-status-url]: https://github.com/mikesposito/secured/actions/workflows/build-lint-test.yml/badge.svg

A very fast CLI tool for encryption and decryption of large amounts of data

![](./.github/assets/secured.gif)

> [!WARNING]
> As this crate is under early development, APIs are rapidly changing, and so is the documentation. 

## Features
- **Encryption and Decryption**: Easily encrypt and decrypt files with password or a pre-generated encryption key.
- **Key Derivation**: Generate encryption keys from passwords with customizable iterations and salt.
- **File Inspection**: Inspect details of secured files.

### 🔬 Benchmark Summary

We benchmarked three configurations of ChaCha20 encryption over **1 GiB of data** using **1,000 blocks per thread** on an **AMD Ryzen 9 9900X**. The results demonstrate a clear trade-off between performance and authentication strategy:

| Cipher Configuration          | Time (ms)               | Throughput (GiB/s)       | Notes                            |
|------------------------------|-------------------------|---------------------------|----------------------------------|
| ChaCha20 only                | 7.23 – 7.31 ms          | **13.36 – 13.50 GiB/s**   | Fastest (no authentication)     |
| ChaCha20 + BLAKE3 (signed)   | 37.35 – 37.71 ms        | **2.59 – 2.61 GiB/s**     | High-speed MAC, good balance    |
| ChaCha20 + Poly1305 (signed) | 56.81 – 57.23 ms        | **1.71 – 1.72 GiB/s**     | RFC-compliant AEAD, slowest     |

- **ChaCha20 only** offers maximum performance but does not provide authentication.
- **ChaCha20 + BLAKE3** is a high-performance authenticated option that takes advantage of BLAKE3’s parallel design.
- **ChaCha20 + Poly1305** follows the AEAD construction as specified in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) but is significantly slower due to the serial nature of Poly1305.

## Installation
To use **secured** as a CLI tool or integrate it into your Rust project, ensure you have Rust installed, then:

### As a CLI tool
```sh
cargo install secured
```

### As a Library
```sh
cargo add secured
```
## Usage
### Encrypting a Single File
Encrypt a single file with a password. If no password is provided, the tool will prompt you for it.
```sh
secured encrypt secret.txt
```

### Decrypting a Single File
Decrypt a single file with a password. If no password is provided, the tool will prompt you for it.
```sh
secured decrypt secret.txt.secured
```

### Encrypting/Decrypting Multiple Files with Glob Patterns
Use glob patterns to encrypt or decrypt multiple files with a single command.
```sh
secured encrypt data/*.txt
secured decrypt data/*.txt.secured
```

### Generating Encryption Key
Generate an encryption key from a password with customizable iterations and salt.
```sh
secured key --password my_secret_password --iterations 1000000 --salt abcdef1234567890
```

### Inspecting Secured Files
Inspect details of one or more secured files.
```sh
secured inspect secret.txt.secured
secured inspect data/*.txt.secured
```

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.
## License
Secured is distributed under the MIT License. See `LICENSE` for more information.
```
