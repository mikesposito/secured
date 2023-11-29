use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{OsRng, RngCore};
use sha3::Keccak256;

/// A Public Key & Salt pair that can be used for simmetric encryption,
/// compatible with ChaCha20Poly1305
pub struct EncryptionKey {
  pub pubk: [u8; 32],
  pub salt: [u8; 16],
}

impl EncryptionKey {
  /// Create a new EncryptionKey from a password and a number of rounds
  pub fn new(password: &[u8], rounds: u32) -> Self {
    // Salt generation
    let mut salt = [0; 16];
    OsRng.fill_bytes(&mut salt);

    // Key derivation
    let mut pubk = [0; 32];
    if pbkdf2::<Hmac<Keccak256>>(password, &salt, rounds, &mut pubk).is_err() {
      panic!("Key derivation failed")
    }

    Self { pubk, salt }
  }

  /// Create a new EncryptionKey from a password and a salt, and
  /// passing a number of rounds
  pub fn with_salt(password: &[u8], salt: [u8; 16], rounds: u32) -> Self {
    // Key derivation
    let mut pubk = [0; 32];
    if pbkdf2::<Hmac<Keccak256>>(password, &salt, rounds, &mut pubk).is_err() {
      panic!("Key derivation failed")
    }

    Self { pubk, salt }
  }
}
