/// Provides a high-level interface for the ChaCha20 cipher algorithm.
///
/// This module wraps the lower-level `ChaChaStream` to offer a straightforward API for encryption and decryption.
/// It utilizes the `Cipher` trait for defining common cryptographic operations.
pub mod core;
pub mod stream;

use crate::{Bytes, Cipher, Slice};
use stream::ChaChaStream;

/// Represents the ChaCha20 encryption/decryption cipher.
///
/// This struct encapsulates `ChaChaStream` to handle the cipher's state and operations.
/// It provides an interface for initializing the cipher with a key and IV (initialization vector),
/// as well as for performing encryption and decryption operations.
pub struct ChaCha20 {
  pub stream: ChaChaStream,
}

impl ChaCha20 {
  /// Constructs a new `ChaCha20` cipher instance.
  ///
  /// Initializes the internal `ChaChaStream` with the provided key and IV (initialization vector).
  /// This setup is necessary for both encryption and decryption operations.
  ///
  /// # Arguments
  /// * `key` - A 256-bit key represented as 32 bytes.
  /// * `iv` - A 64-bit IV (nonce) represented as 8 bytes.
  ///
  /// # Returns
  /// A new instance of `ChaCha20`.
  pub fn new(key: [u8; 32], iv: [u8; 8]) -> Self {
    Self {
      stream: ChaChaStream::new(key, iv),
    }
  }
}

impl Cipher for ChaCha20 {
  /// Encrypts the provided data using the ChaCha20 algorithm.
  ///
  /// This method processes the input slice and returns the encrypted data as a byte vector.
  /// It utilizes the internal `ChaChaStream` for the encryption process.
  ///
  /// # Arguments
  /// * `data` - A slice of data to be encrypted.
  ///
  /// # Returns
  /// A `Bytes` vector containing the encrypted data.
  fn encrypt(&mut self, data: &Slice) -> Bytes {
    self.stream.process(data)
  }

  /// Decrypts the provided data using the ChaCha20 algorithm.
  ///
  /// This method processes the input slice and returns the decrypted data as a byte vector.
  /// Due to the symmetric nature of the ChaCha20 algorithm, the decryption process is identical to the encryption process.
  ///
  /// # Arguments
  /// * `data` - A slice of encrypted data to be decrypted.
  ///
  /// # Returns
  /// A `Bytes` vector containing the decrypted data.
  fn decrypt(&mut self, data: &Slice) -> Bytes {
    self.stream.process(data)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const KEY: [u8; 32] = [2; 32];
  const IV: [u8; 8] = [255; 8];
  const PLAINTEXT: [u8; 64] = [0; 64];
  const CIPHERTEXT: [u8; 64] = [
    252, 239, 233, 9, 94, 65, 152, 139, 167, 124, 231, 72, 105, 220, 6, 152, 193, 163, 210, 194,
    62, 218, 243, 150, 175, 108, 22, 115, 75, 241, 206, 29, 70, 66, 93, 244, 184, 171, 27, 184,
    223, 227, 166, 85, 119, 130, 32, 185, 224, 160, 188, 158, 197, 65, 193, 59, 124, 40, 113, 185,
    82, 103, 124, 182,
  ];

  #[test]
  fn it_should_encrypt_data() {
    let mut cipher = ChaCha20::new(KEY, IV);
    let encrypted_data = cipher.encrypt(&PLAINTEXT);

    assert_eq!(encrypted_data.len(), 64);
    assert_eq!(encrypted_data, CIPHERTEXT);
  }

  #[test]
  fn it_should_decrypt_data() {
    let mut cipher = ChaCha20::new(KEY, IV);
    let decrypted_data = cipher.decrypt(&CIPHERTEXT);

    assert_eq!(decrypted_data.len(), 64);
    assert_eq!(decrypted_data, PLAINTEXT);
  }
}
