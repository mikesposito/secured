use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

/// The type of the public key resulting from the derivation function.
/// This is a 32-byte array (256 bits)
pub type PublicKey = [u8; 32];

/// The type of the salt value used in the key derivation function.
/// This is a generic type, and the size is specified as a type parameter.
pub type Salt<const S: usize> = [u8; S];

/// `Key` holds a public key and a salt value.
/// This struct is specifically designed for use in symmetric encryption,
/// and is compatible with multiple encryption algorithms.
pub struct Key<const SALT_SIZE: usize> {
  /// Public key.
  pub pubk: PublicKey,

  /// Salt value.
  pub salt: Salt<SALT_SIZE>,
}

impl<const SALT_SIZE: usize> Key<SALT_SIZE> {
  /// Constructs a new `Key` using a specified password and a number of rounds for key derivation.
  /// The method automatically generates a random salt for each key.
  ///
  /// # Arguments
  /// * `password` - A byte slice representing the password from which the key will be derived.
  /// * `rounds` - The number of iterations used in the PBKDF2 key derivation function.
  ///
  /// # Returns
  /// An instance of `Key` containing the derived public key and the generated salt.
  ///
  /// # Panics
  /// Panics if the key derivation fails.
  pub fn new(password: &[u8], rounds: u32) -> Self {
    // Generate a random salt value
    let salt = random_bytes::<SALT_SIZE>();

    // Derive the public key using PBKDF2 algorithm
    let mut pubk: PublicKey = [0; 32];
    if pbkdf2::<Hmac<Sha256>>(password, &salt, rounds, &mut pubk).is_err() {
      panic!("Key derivation failed")
    }

    Self { pubk, salt }
  }

  /// Constructs a new `Key` using a specified password, a provided salt, and a number of rounds for key derivation.
  ///
  /// # Arguments
  /// * `password` - A byte slice representing the password from which the key will be derived.
  /// * `salt` - An array representing the salt to be used in the key derivation.
  /// * `rounds` - The number of iterations used in the PBKDF2 key derivation function.
  ///
  /// # Returns
  /// An instance of `Key` containing the derived public key and the provided salt.
  ///
  /// # Panics
  /// Panics if the key derivation fails.
  pub fn with_salt(password: &[u8], salt: [u8; SALT_SIZE], rounds: u32) -> Self {
    // Derive the public key using PBKDF2 algorithm with the provided salt
    let mut pubk: PublicKey = [0; 32];
    if pbkdf2::<Hmac<Sha256>>(password, &salt, rounds, &mut pubk).is_err() {
      panic!("Key derivation failed")
    }

    Self { pubk, salt }
  }
}

/// Generates a random byte array of a specified size.
pub fn random_bytes<const S: usize>() -> [u8; S] {
  let mut bytes = [0; S];
  OsRng.fill_bytes(&mut bytes);
  bytes
}
