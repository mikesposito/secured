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
