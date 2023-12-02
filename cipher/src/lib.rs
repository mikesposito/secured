//! # Secured-Cipher Library
//!
//! `secured-cipher` is a Rust library offering an implementation of the ChaCha20 and XChaCha20 encryption algorithms.
//! It provides both high-level and low-level cryptographic functionalities through a common interface.
//!
//! ## Overview
//!
//! The library includes the following key components:
//!
//! - `ChaCha20`: A struct for the ChaCha20 stream cipher algorithm.
//! - `XChaCha20`: A struct for the XChaCha20 stream cipher algorithm.
//! - `Cipher`: A struct that provides a common interface for cryptographic operations, focusing on encryption and decryption.
//! - `CipherMode`: An enum to specify the mode of the cipher (ChaCha20 or XChaCha20).
//!
//! ## Features
//!
//! - High-level interfaces for ChaCha20 and XChaCha20 ciphers.
//! - Common `Cipher` interface for encryption and decryption operations.
//! - Flexible usage with support for both raw and high-level cryptographic operations.
//!
//! ## Usage
//!
//! ### Basic Encryption and Decryption
//!
//! This example demonstrates encrypting and decrypting data using the ChaCha20 cipher.
//!
//! ```rust
//! use secured_cipher::Cipher;
//!
//! let key: [u8; 32] = [0; 32]; // Your key
//! let nonce: [u8; 12] = [0; 12]; // Your nonce
//! let data: &[u8] = b"Your data here"; // Data to be encrypted
//!
//! let mut cipher = Cipher::default();
//! cipher.init(&key, &nonce);
//!
//! let encrypted_data = cipher.encrypt(data);
//! println!("Encrypted data: {:?}", encrypted_data);
//!
//! let decrypted_data = cipher.decrypt(&encrypted_data);
//! println!("Decrypted data: {:?}", decrypted_data);
//! ```
//!
//! ## Modules
//!
//! - `core`: Core functionalities and algorithmic implementations.
//! - `stream`: Internal stream cipher operations, including `ChaChaStream`.

pub mod permutation;

pub use secured_cipher_key::{random_bytes, Key};

use permutation::{ChaCha20, Permutation};

/// The `Cipher` struct provides a common interface for cryptographic operations,
/// specifically focusing on encryption and decryption.
pub struct Cipher {
  /// The cipher's internal permutation logic.
  permutation: Box<dyn Permutation>,
}

pub enum CipherMode {
  ChaCha20,
  // TODO: XChaCha20,
}

impl Cipher {
  /// Constructs a new `Cipher` instance using the specified cipher mode.
  ///
  /// # Arguments
  /// * `mode` - The mode of cipher (ChaCha20 or XChaCha20) to use.
  ///
  /// # Returns
  /// A new instance of `Cipher`.
  pub fn new(mode: CipherMode) -> Self {
    let permutation: Box<dyn Permutation> = match mode {
      CipherMode::ChaCha20 => Box::new(ChaCha20::new()),
      // TODO: CipherMode::XChaCha20 => Box::new(XChaCha20::new()),
    };

    Self { permutation }
  }

  /// Initializes the cipher with a key and IV (initialization vector).
  /// Sets up the cipher's internal state for encryption or decryption.
  ///
  /// # Arguments
  /// * `key` - A byte slice representing the key.
  /// * `iv` - A byte slice representing the initialization vector.
  ///
  /// # Returns
  /// A mutable reference to the cipher instance.
  pub fn init(&mut self, key: &[u8], iv: &[u8]) -> &mut Self {
    self.permutation.init(key, iv);
    self
  }

  /// Encrypts the provided data.
  ///
  /// # Arguments
  /// * `data` - A slice of data to be encrypted.
  ///
  /// # Returns
  /// Encrypted data as a vector of bytes (`Bytes`).
  pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
    self.permutation.process(data)
  }

  /// Decrypts the provided data.
  ///
  /// # Arguments
  /// * `data` - A slice of encrypted data to be decrypted.
  ///
  /// # Returns
  /// Decrypted data as a vector of bytes (`Bytes`).
  pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
    self.permutation.process(data)
  }
}

impl Default for Cipher {
  /// Provides a default instance of `Cipher` using the XChaCha20 mode.
  ///
  /// # Returns
  /// A new instance of `Cipher` with XChaCha20 mode.
  fn default() -> Self {
    Self::new(CipherMode::ChaCha20)
  }
}
