#![forbid(unsafe_code)]

/// `secured` is a Rust-based solution focused on providing robust and secure symmetric encryption functionalities. It primarily utilizes the ChaCha20Poly1305 algorithm and offers a suite of tools for key generation, encryption, decryption, and secure data encapsulation.
///
/// ## Features
/// - **ChaCha20Poly1305Cipher**: Implements the ChaCha20Poly1305 encryption and decryption algorithm.
/// - **EncryptionKey**: Manages encryption keys, including creation and derivation from passwords.
/// - **Enclave**: A generic container for securely storing encrypted data along with unencrypted metadata.
/// - **Custom Error Handling**: Defines and manages custom error types specific to the encryption processes.
///
/// ## Getting Started
///
/// ### Prerequisites
/// Ensure you have the latest version of Rust and Cargo installed on your system.
///
/// ### Installation
/// Add the following to your `Cargo.toml` file:
/// ```toml
/// [dependencies]
/// your-encryption-library = "0.1.0"
/// ```
///
/// ### Basic Usage
/// Here's a quick example to get you started:
///
/// ```rust
/// use secured::enclave::{ChaCha20Poly1305Cipher, EncryptionKey, Enclave, CipherKey};
///
/// fn main() {
///   // Key generation
///   let key = EncryptionKey::new(b"my password", 1_000); // 1k rounds are too low for production use
///
///   // Use the Enclave to encrypt data
///   let enclave = Enclave::from_plain_bytes("some metadata", &key.pubk, b"some bytes to encrypt".to_vec()).unwrap();
///   
///   // Decrypt the enclave
///   let recovered_bytes = enclave.decrypt(&key.pubk);
/// }
/// ```
pub use enclave;
