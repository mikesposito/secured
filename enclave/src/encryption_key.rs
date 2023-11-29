use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

/// `EncryptionKey` holds a public key and a salt value.
/// This struct is specifically designed for use in symmetric encryption,
/// and is compatible with the ChaCha20Poly1305 encryption algorithm.
pub struct EncryptionKey {
  /// Public key, 32 bytes in length.
  pub pubk: [u8; 32],

  /// Salt value, 16 bytes in length, used in the key derivation process.
  pub salt: [u8; 16],
}

impl EncryptionKey {
  /// Constructs a new `EncryptionKey` using a specified password and a number of rounds for key derivation.
  /// The method automatically generates a random salt for each key.
  ///
  /// # Arguments
  /// * `password` - A byte slice representing the password from which the key will be derived.
  /// * `rounds` - The number of iterations used in the PBKDF2 key derivation function.
  ///
  /// # Returns
  /// An instance of `EncryptionKey` containing the derived public key and the generated salt.
  ///
  /// # Panics
  /// Panics if the key derivation fails.
  pub fn new(password: &[u8], rounds: u32) -> Self {
    // Generate a random salt value
    let mut salt = [0; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive the public key using PBKDF2 algorithm
    let mut pubk = [0; 32];
    if pbkdf2::<Hmac<Sha256>>(password, &salt, rounds, &mut pubk).is_err() {
      panic!("Key derivation failed")
    }

    Self { pubk, salt }
  }

  /// Constructs a new `EncryptionKey` using a specified password, a provided salt, and a number of rounds for key derivation.
  ///
  /// # Arguments
  /// * `password` - A byte slice representing the password from which the key will be derived.
  /// * `salt` - A 16-byte array representing the salt to be used in the key derivation.
  /// * `rounds` - The number of iterations used in the PBKDF2 key derivation function.
  ///
  /// # Returns
  /// An instance of `EncryptionKey` containing the derived public key and the provided salt.
  ///
  /// # Panics
  /// Panics if the key derivation fails.
  pub fn with_salt(password: &[u8], salt: [u8; 16], rounds: u32) -> Self {
    // Derive the public key using PBKDF2 algorithm with the provided salt
    let mut pubk = [0; 32];
    if pbkdf2::<Hmac<Sha256>>(password, &salt, rounds, &mut pubk).is_err() {
      panic!("Key derivation failed")
    }

    Self { pubk, salt }
  }
}
