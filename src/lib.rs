#![forbid(unsafe_code)]

/// `secured` - A Rust-based Cryptographic Library
///
/// This library focuses on providing robust and secure symmetric encryption functionalities, 
/// primarily utilizing the ChaCha20 and ChaCha20Poly1305 algorithms. It offers a comprehensive suite of tools 
/// for key generation, encryption, decryption, and secure data encapsulation, making it suitable 
/// for a wide range of cryptographic needs.
///
/// ## Features
/// - **ChaCha20**: A high-level struct for the ChaCha20 cipher algorithm, offering encryption and decryption functionalities.
/// - **ChaChaStream**: A core struct that manages the internal state and operations of the ChaCha20 cipher, providing lower-level control.
/// - **ChaCha20Poly1305Cipher**: Implements the combined ChaCha20 and Poly1305 encryption and decryption algorithm for authenticated encryption.
/// - **Key**: Manages cryptographic keys, enabling creation and derivation of keys from passwords, ensuring secure key management.
/// - **Enclave**: A secure container for encrypted data, paired with unencrypted metadata, providing a convenient and safe way to handle sensitive information.
/// - **Cipher**: A trait defining a standard interface for cryptographic operations like encryption and decryption.
/// - **Custom Error Handling**: Offers custom error types tailored to encryption processes, enhancing error reporting and handling in cryptographic operations.
///
/// ## Getting Started
///
/// ### Prerequisites
/// - Ensure you have the latest version of Rust and Cargo installed on your system for seamless integration.
///
/// ### Installation
/// To use `secured` in your project, add it as a dependency in your `Cargo.toml` file:
/// ```toml
/// [dependencies]
/// secured = "0.1.2" // Use the latest version available
/// ```
///
/// ### Basic Usage
/// Here's a quick example to illustrate basic usage of the `secured` library:
///
/// ```rust
/// use secured::{enclave::Enclave, cipher::Key};
///
/// fn main() {
///     // Key generation: Create a new cryptographic key using a password and iteration count.
///     // Note: In a production environment, ensure to use a higher iteration count for added security.
///     let key: Key<32, 16> = Key::new(b"my password", 1_000);
///
///     // Encrypt data: Utilize the Enclave to securely encrypt data along with metadata.
///     let enclave = Enclave::from_plain_bytes("some metadata", key.pubk, b"some bytes to encrypt".to_vec()).unwrap();
///   
///     // Decrypt data: Recover the original bytes from the encrypted enclave.
///     let recovered_bytes = enclave.decrypt(key.pubk);
/// }
/// ```
/// 
/// This basic example demonstrates key generation, data encryption, and decryption using the `Enclave`.
/// For more detailed usage and advanced features, refer to the module documentation.
pub use enclave;
pub use cipher;
