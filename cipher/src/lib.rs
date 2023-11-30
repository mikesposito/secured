//! # Secured-Cipher Library
//!
//! This library, `secured-cipher`, provides an implementation of the ChaCha20 encryption algorithm,
//! along with a common cryptographic interface defined by the `Cipher` trait.
//! The library is structured to offer both low-level and high-level cryptographic functionalities.
//!
//! ## Overview
//!
//! - `ChaCha20`: A struct that provides a high-level interface for the ChaCha20 stream cipher algorithm.
//!   It offers methods for encryption and decryption operations, simplifying the use of the underlying `ChaChaStream`.
//! - `ChaChaStream`: A struct that handles the core state and operations of the ChaCha20 cipher.
//!   It is used internally by `ChaCha20` but can also be used directly for lower-level control.
//! - `Cipher`: A trait that defines a standard interface for cryptographic operations,
//!   specifically focusing on encryption and decryption methods.
//! - Type aliases (`Slice`, `Key`, `Nonce`, `Bytes`): These simplify the usage of common cryptographic data types
//!   such as keys, nonces, and byte slices.
//!
//! ## Usage
//!
//! ### Encrypting Data with ChaCha20
//!
//! ```rust
//! use secured_cipher::{chacha20::ChaCha20, Cipher, Slice};
//!
//! let key: [u8; 32] = [0; 32]; // Replace with your key
//! let nonce: [u8; 8] = [0; 8]; // Replace with your nonce
//! let data: &[u8] = b"Your data here"; // Data to be encrypted
//!
//! let mut cipher = ChaCha20::new(key, nonce);
//! let encrypted_data = cipher.encrypt(data);
//! println!("Encrypted data: {:?}", encrypted_data);
//! ```
//!
//! ### Decrypting Data with ChaCha20
//!
//! ```rust
//! use secured_cipher::{chacha20::ChaCha20, Cipher, Slice};
//!
//! let key: [u8; 32] = [0; 32]; // Replace with your key
//! let nonce: [u8; 8] = [0; 8]; // Replace with your nonce
//! let encrypted_data: &[u8] = &[0x1, 0x2, 0x3, 0x4]; // Replace with your encrypted data
//!
//! let mut cipher = ChaCha20::new(key, nonce);
//! let decrypted_data = cipher.decrypt(encrypted_data);
//! println!("Decrypted data: {:?}", decrypted_data);
//! ```
//!
//! ## Modules
//!
//! - `core`: Contains core functionalities and algorithmic implementations.
//! - `stream`: Provides the `ChaChaStream` struct and related functions for internal stream cipher operations.
//!
//! This library aims to provide an easy-to-use and efficient implementation of the ChaCha20 cipher,
//! suitable for various cryptographic needs. Whether you need high-level interfaces with `ChaCha20`
//! or low-level control with `ChaChaStream`, `secured-cipher` is equipped to meet your cryptographic requirements.

pub use secured_cipher_key::{random_bytes, Key};
pub mod chacha20;

/// A type alias for representing a slice of bytes.
/// This is commonly used for raw data input/output in cryptographic operations.
pub type Slice = [u8];

/// Type alias for unencrypted and encrypted data represented as a vector of bytes.
/// This is used for the output of cryptographic operations, like the result of encryption or decryption.
pub type Bytes = Vec<u8>;

/// The `Cipher` trait defines a common interface for cryptographic operations, specifically encryption and decryption.
///
/// This trait is meant to be implemented by specific cryptographic algorithms, providing a consistent interface
/// for performing these operations across different types of ciphers.
pub trait Cipher {
  /// Encrypts the provided data.
  ///
  /// Takes a slice of data (`&Slice`) and returns an encrypted version of it as a vector of bytes (`Bytes`).
  /// The exact nature of the encryption depends on the implementation of the trait.
  ///
  /// # Arguments
  /// * `data` - A slice of data to be encrypted.
  ///
  /// # Returns
  /// Encrypted data as a vector of bytes.
  fn encrypt(&mut self, data: &Slice) -> Bytes;

  /// Decrypts the provided data.
  ///
  /// Takes a slice of encrypted data (`&Slice`) and returns a decrypted version of it as a vector of bytes (`Bytes`).
  /// The decryption process depends on the specific implementation of the trait and should reverse the effects of the corresponding `encrypt` method.
  ///
  /// # Arguments
  /// * `data` - A slice of encrypted data to be decrypted.
  ///
  /// # Returns
  /// Decrypted data as a vector of bytes.
  fn decrypt(&mut self, data: &Slice) -> Bytes;
}
