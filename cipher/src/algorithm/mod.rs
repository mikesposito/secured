/// Module for the ChaCha20 stream cipher algorithm.
pub mod chacha20;

/// Module for the Poly1305 message authentication code (MAC) algorithm.
pub mod poly1305;

/// Module for the Blake3 message authentication code (MAC) algorithm.
pub mod blake3;

/// Re-exporting `ChaCha20` for direct use.
pub use chacha20::ChaCha20;

/// Re-exporting `Poly1305` for direct use.
pub use poly1305::{Poly1305, SignedEnvelope};

/// Re-exporting `Blake3Mac` for direct use.
pub use blake3::Blake3Mac;

pub trait AlgorithmKeyIVInit {
  /// Initializes the algorithm with a key and an initialization vector (IV).
  ///
  /// This method sets up the internal state of the cipher using the provided key and IV,
  /// preparing it for either encryption or decryption.
  ///
  /// # Arguments
  /// * `key` - A byte slice representing the cryptographic key.
  /// * `iv` - A byte slice representing the initialization vector.
  fn init(&mut self, key: &[u8], iv: &[u8]);
}

pub trait AlgorithmKeyInit {
  /// Initializes the algorithm with a key.
  ///
  /// This method sets up the internal state of the cipher using the provided key,
  /// preparing it for either encryption or decryption.
  ///
  /// # Arguments
  /// * `key` - A byte slice representing the cryptographic key.
  fn init(&mut self, key: &[u8]);
}

pub trait AlgorithmProcess {
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
  fn process(&mut self, data: Vec<u8>) -> Vec<u8>;
}

pub trait AlgorithmProcessInPlace {
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
  fn process_in_place(&self, data: &mut [u8]);
}

pub trait AlgorithmCore: AlgorithmKeyIVInit + AlgorithmProcess + AlgorithmProcessInPlace {}

pub trait EncryptionAlgorithm:
  AlgorithmKeyIVInit + AlgorithmProcess + AlgorithmProcessInPlace
{
}

pub trait AEADAlgorithm: AlgorithmKeyInit + AlgorithmProcess {}
