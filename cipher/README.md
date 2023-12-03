# Secured-Cipher Library

## Overview
`secured-cipher` is a Rust library offering an implementation of the `ChaCha20` and `Poly1305` algorithms. It provides both high-level and low-level cryptographic functionalities through a common interface.

## Features
- High-level interfaces for `ChaCha20` cipher and `Poly1305` authenticator.
- Common `Cipher` interface for encryption and decryption operations.
- `core` module with low-level crypto operations
- Flexible usage with support for both raw and high-level cryptographic operations.

## Basic Encryption and Decryption Example
Encrypt and decrypt data using the ChaCha20 cipher:

```rust
use secured_cipher::Cipher;

let key: [u8; 32] = [0; 32]; // Your key
let nonce: [u8; 12] = [0; 12]; // Your nonce
let data: &[u8] = b"Your data here"; // Data to be encrypted

let mut cipher = Cipher::default();
cipher.init(&key, &nonce);

// Encrypt and decrypt
let encrypted_data = cipher.encrypt(data);
let decrypted_data = cipher.decrypt(&encrypted_data);

// Sign
let signed_secret_envelope = cipher.sign(b"your readable header", &encrypted_data);

// Decrypt and verify
let verified_decrypted_data = cipher.decrypt_and_verify(&signed_secret_envelope);
assert!(verified_decrypted_data.is_ok());

println!("Decrypted and verified data: {:?}", verified_decrypted_data.unwrap());
```

## Installation
Add `secured-cipher` to your Cargo.toml:

```toml
[dependencies]
secured-cipher = "~0.2.0"
```