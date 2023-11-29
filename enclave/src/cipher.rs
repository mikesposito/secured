use chacha20poly1305::{
  aead::{Aead, NewAead},
  XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};

/// Type alias for a 32-byte cipher key.
pub type CipherKey = [u8; 32];

/// Type alias for a 24-byte cipher nonce.
pub type CipherNonce = [u8; 24];

/// Type alias for encrypted data represented as a vector of bytes.
pub type EncryptedBytes = Vec<u8>;

/// `ChaCha20Poly1305Cipher` provides functionality for encryption and decryption using the
/// ChaCha20Poly1305 algorithm.
pub struct ChaCha20Poly1305Cipher;

impl ChaCha20Poly1305Cipher {
  /// Generates a new 32-byte cipher key for ChaCha20Poly1305 encryption.
  ///
  /// # Returns
  /// A randomly generated 32-byte `CipherKey`.
  pub fn new_key() -> CipherKey {
    let mut key = [0; 32];
    OsRng.fill_bytes(&mut key);
    key
  }

  /// Encrypts data using ChaCha20Poly1305 with a specified key and a randomly generated nonce.
  ///
  /// # Arguments
  /// * `key` - A 32-byte array used as the encryption key.
  /// * `data` - The data to be encrypted as a byte slice.
  ///
  /// # Returns
  /// A `Result` containing either the encrypted data and the nonce used for encryption,
  /// or an error message if encryption fails.
  pub fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<(EncryptedBytes, CipherNonce), String> {
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);

    Ok((chacha20poly1305_encrypt((key, &nonce), data)?, nonce))
  }

  /// Decrypts data using ChaCha20Poly1305 with a specified key and nonce.
  ///
  /// # Arguments
  /// * `key` - A 32-byte array used as the decryption key.
  /// * `nonce` - A 24-byte array representing the nonce used during encryption.
  /// * `data` - The encrypted data as a byte slice.
  ///
  /// # Returns
  /// A `Result` containing either the decrypted plaintext as a vector of bytes,
  /// or an error message if decryption fails.
  pub fn decrypt(
    key: &CipherKey,
    nonce: &CipherNonce,
    data: &[u8],
  ) -> Result<EncryptedBytes, String> {
    chacha20poly1305_decrypt((key, nonce), data)
  }
}

/// Encrypts data using the XChaCha20Poly1305 algorithm.
///
/// # Arguments
/// * `(key, nonce)` - A tuple containing a 32-byte encryption key and a 24-byte nonce.
/// * `data` - The data to be encrypted as a byte slice.
///
/// # Returns
/// A `Result` containing either the encrypted data as a vector of bytes,
/// or an error message if encryption fails.
fn chacha20poly1305_encrypt(
  (key, nonce): (&[u8; 32], &[u8; 24]),
  data: &[u8],
) -> Result<Vec<u8>, String> {
  let cipher = match XChaCha20Poly1305::new_from_slice(key) {
    Ok(cipher) => cipher,
    Err(_) => return Err("Invalid cipher key".to_string()),
  };

  match cipher.encrypt(nonce.into(), data) {
    Ok(ciphertext) => Ok(ciphertext),
    Err(_) => Err("Encryption failed".to_string()),
  }
}

/// Decrypts data using the XChaCha20Poly1305 algorithm.
///
/// # Arguments
/// * `(key, nonce)` - A tuple containing a 32-byte decryption key and a 24-byte nonce.
/// * `data` - The encrypted data as a byte slice.
///
/// # Returns
/// A `Result` containing either the decrypted plaintext as a vector of bytes,
/// or an error message if decryption fails.
fn chacha20poly1305_decrypt(
  (key, nonce): (&[u8; 32], &[u8; 24]),
  data: &[u8],
) -> Result<Vec<u8>, String> {
  let cipher = match XChaCha20Poly1305::new_from_slice(key) {
    Ok(cipher) => cipher,
    Err(_) => return Err("Invalid cipher key".to_string()),
  };

  match cipher.decrypt(nonce.into(), data) {
    Ok(plaintext) => Ok(plaintext),
    Err(_) => Err("Decryption failed".to_string()),
  }
}
