/// Core module containing essential cryptographic functionalities.
pub mod core;

/// Module for the ChaCha20 stream cipher algorithm.
pub mod chacha20;

/// Module for the XChaCha20 stream cipher algorithm, an extended variant of ChaCha20.
pub mod xchacha20;

/// Re-exporting `ChaCha20` for direct use.
pub use chacha20::ChaCha20;

/// Re-exporting `XChaCha20` for direct use.
pub use xchacha20::XChaCha20;

/// `Permutation` trait defines the common operations for permutation-based cryptographic algorithms.
///
/// This trait provides the fundamental methods required for encryption and decryption processes
/// in ciphers like ChaCha20 and XChaCha20.
pub trait Permutation {
  /// Initializes the permutation with a key and an initialization vector (IV).
  ///
  /// This method sets up the internal state of the cipher using the provided key and IV,
  /// preparing it for either encryption or decryption.
  ///
  /// # Arguments
  /// * `key` - A byte slice representing the cryptographic key.
  /// * `iv` - A byte slice representing the initialization vector.
  fn init(&mut self, key: &[u8], iv: &[u8]);

  /// Processes the provided data (either encrypts or decrypts, depending on the implementation).
  ///
  /// This method applies the cipher's permutation logic to the provided data, returning the
  /// processed data as a new vector of bytes.
  ///
  /// # Arguments
  /// * `data` - A byte slice of data to be processed (encrypted or decrypted).
  ///
  /// # Returns
  /// A vector of bytes representing the processed data.
  fn process(&mut self, data: &[u8]) -> Vec<u8>;

  /// Clears the internal state of the cipher.
  ///
  /// This method is used to reset the cipher's state, ensuring that no sensitive information
  /// is left in memory after the cryptographic operations are complete.
  fn clear(&mut self);
}
