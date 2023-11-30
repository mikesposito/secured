# secured

Secured is a versatile Rust package that provides robust encryption and decryption capabilities. It can be seamlessly integrated as a library in other Rust applications or used as a standalone command-line interface (CLI) tool.

> [!WARNING]
> This crate is under development and APIs are rapidly changing (including this README!). Make sure to lock to a specific crate version to avoid updates.

## Features

- **Encryption and Decryption**: Easily encrypt and decrypt files with password, safely.
  - A `ChaCha20` cipher is used, with a 32-bytes long encryption key, a 2-words `IV`, and a 2-words `counter`.
    The cipher encrypts bytes dividing them in 64-bytes chunks, and processing each chunk in parallel.
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

```rust
use secured::enclave::Enclave;
use secured::cipher::Key;

fn main() {
   // Key generation (32bytes for the key, 16 bytes for salt)
   let key = Key::<32, 16>::new(b"my password", 900_000); // 900K rounds

   // Using Enclave for data encapsulation
   let enclave =
      Enclave::from_plain_bytes("Some metadata", key.pubk, b"Some bytes to encrypt".to_vec())
         .unwrap();

   // Get encrypted bytes (ciphertext)
   println!("Encrypted bytes: {:?}", enclave.encrypted_bytes);

   // Decrypt Enclave
   let decrypted_bytes = enclave.decrypt(key.pubk).unwrap();

   assert_eq!(decrypted_bytes, b"Some bytes to encrypt");
}
```

See [package documentation](https://docs.rs/secured/0.1.1/) for more information

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

Secured is distributed under the MIT License. See `LICENSE` for more information.
