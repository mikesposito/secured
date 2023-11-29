use chacha20poly1305::{
  aead::{Aead, NewAead},
  XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};

pub type CipherKey = [u8; 32];
pub type CipherNonce = [u8; 24];
pub type EncryptedBytes = Vec<u8>;

pub struct ChaCha20Poly1305Cipher;

impl ChaCha20Poly1305Cipher {
  /// Generate a new 32 bytes long cipher key
  /// for ChaCha20Poly1305
  pub fn new_key() -> CipherKey {
    let mut key = [0; 32];
    OsRng.fill_bytes(&mut key);
    key
  }

  /// Encrypt data with ChaCha20Poly1305, using the passed key
  /// and a randomly generated 24 bytes long nonce.
  pub fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<(EncryptedBytes, CipherNonce), String> {
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);

    Ok((chacha20poly1305_encrypt((key, &nonce), data)?, nonce))
  }

  /// Decrypt data with ChaCha20Poly1305, using the passed key and nonce.
  pub fn decrypt(
    key: &CipherKey,
    nonce: &CipherNonce,
    data: &[u8],
  ) -> Result<EncryptedBytes, String> {
    chacha20poly1305_decrypt((key, nonce), data)
  }
}

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
