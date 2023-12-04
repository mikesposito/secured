# secured

Secured is a versatile Rust package that provides robust encryption and decryption capabilities. It can be seamlessly integrated as a library in other Rust applications or used as a standalone command-line interface (CLI) tool.

> [!WARNING]
> This crate is under development and APIs are rapidly changing (including this README!). Make sure to lock to a specific crate version to avoid updates.

## Features

- **Encryption and Decryption**: Easily encrypt and decrypt files with password, using [the `ChaCha20` and `Poly1305` algorithms combined](cipher/README.md).
- **Cli & Library**: Use as a standalone CLI tool or integrate as a library in your Rust applications.

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

### As a CLI Tool

Secured is straightforward to use from the command line. Here are the basic commands:

1. **Encryption**

   ```sh
   secured encrypt <FILE> [PASSWORD]
   ```

   Encrypts the specified `<FILE>`. An optional `[PASSWORD]` can be passed directly to the command.

2. **Decryption**
   ```sh
   secured decrypt <FILE> [PASSWORD]
   ```
   Decrypts the specified `<FILE>`. An optional `[PASSWORD]` can be passed directly to the command. Obviously, the password must be the same used during encryption.

### As a Library

To use Secured as a library in your Rust application, simply import the package and utilize its encryption and decryption functions as per your requirements.

#### Encrypting Data

```rust
use secured_enclave::{Enclave, Encryptable, KeyDerivationStrategy};

let password = "strong_password";
let encrypted_string = "Hello, world!".encrypt(password.to_string(), KeyDerivationStrategy::default());
```

#### Decrypting Data

```rust
use secured_enclave::{Decryptable, EnclaveError};

let password = "strong_password";
let decrypted_result = encrypted_data.decrypt(password.to_string());

println!("Decrypted data: {:?}", String::from_utf8(decrypted_data).unwrap())
```

See [Enclave documentation](enclave/README.md) for more advanced usage

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

Secured is distributed under the MIT License. See `LICENSE` for more information.
