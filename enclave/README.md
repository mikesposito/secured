# secured-enclave

## Overview

`secured-enclave` is a Rust crate designed for secure and dev-ergonomic encryption and decryption of data. It provides a robust way to encrypt data using various cipher algorithms, key derivation strategies, and support for metadata.

## Features

- **Secure Encryption and Decryption**: Uses ChaCha20Poly1305 for encryption and authentication, ensuring strong security.
- **Metadata Support**: Allows associating metadata with encrypted data.
- **Flexible Key Management**: Supports different key derivation strategies for enhanced security.
- **Serialization and Deserialization**: Easily serialize and deserialize encrypted data for storage or transmission.

## Installation

Add the following line to your `Cargo.toml` file:

```toml
[dependencies]
secured-enclave = "0.5.0"
```

## Usage

### Basic Encryption and Decryption

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

### Advanced Usage

#### Encrypting with Custom Strategies

It is possible to have more control as well when needed:

```rust
use secured_enclave::{Enclave, KeyDerivationStrategy};

fn main() {
   // Key generation (32bytes for the key, 16 bytes for salt)
   let key = Key::<32, 16>::new(b"my password", KeyDerivationStrategy::PBKDF2(900_000)); // 900K iterations

   // Leave some readable metadata (but signed!)
   let metadata = b"some metadata".to_vec();

   // Using Enclave for data encapsulation (&str metadata, 8-byte nonce)
   let enclave =
    Enclave::from_plain_bytes(metadata, key.pubk, b"Some bytes to encrypt".to_vec())
      .unwrap();

   // Get encrypted bytes (ciphertext)
   println!("Encrypted bytes: {:?}", enclave.encrypted_bytes);

   // Serialize everything to bytes
   let bytes: Vec<u8> = enclave.into();

   // Decrypt Enclave
   let decrypted_bytes = enclave.decrypt(key.pubk).unwrap();

   assert_eq!(decrypted_bytes, b"Some bytes to encrypt");
}
```

#### Decrypting with Metadata

```rust
use enclave::{Decryptable, EnclaveError};

let decryption_result = encrypted_data_with_metadata.decrypt_with_metadata::<Vec<u8>>(key);
match decryption_result {
    Ok((decrypted_data, metadata)) => {
        println!("Decrypted data: {:?}", String::from_utf8(decrypted_data).unwrap());
        println!("Metadata: {:?}", String::from_utf8(metadata).unwrap());
    },
    Err(e) => println!("Error during decryption: {:?}", e),
}
```

## Testing

The crate includes a comprehensive set of unit tests. Run the tests with the following command:

```shell
cargo test
```

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## License

This project is licensed under the [MIT license](LICENSE).

---

This README provides a basic guide to getting started with the Enclave crate. For more detailed documentation, please refer to the [API documentation](https://docs.rs/secured-enclave/).
