use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

/// `Key` holds a public key and a salt value.
/// This struct is specifically designed for use in symmetric encryption,
/// and is compatible with multiple encryption algorithms.
pub struct Key<const P: usize, const S: usize> {
  /// Public key.
  pub pubk: [u8; P],

  /// Salt value.
  pub salt: [u8; S],
}

impl<const P: usize, const S: usize> Key<P, S> {
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
  pub fn new(password: &[u8], strategy: KeyDerivationStrategy) -> Self {
    // Generate a random salt value
    let salt = random_bytes::<S>();

    // Derive the public key using PBKDF2 algorithm
    let mut pubk = [0; P];
    match strategy {
      KeyDerivationStrategy::PBKDF2(rounds) => {
        if pbkdf2::<Hmac<Sha256>>(password, &salt, rounds as u32, &mut pubk).is_err() {
          panic!("Key derivation failed")
        }
      }
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
  pub fn with_salt(password: &[u8], salt: [u8; S], strategy: KeyDerivationStrategy) -> Self {
    // Derive the public key using PBKDF2 algorithm with the provided salt
    let mut pubk = [0; P];

    match strategy {
      KeyDerivationStrategy::PBKDF2(rounds) => {
        if pbkdf2::<Hmac<Sha256>>(password, &salt, rounds as u32, &mut pubk).is_err() {
          panic!("Key derivation failed")
        }
      }
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

#[derive(Clone, Debug)]
pub enum KeyDerivationStrategy {
  PBKDF2(usize),
}

impl Default for KeyDerivationStrategy {
  fn default() -> Self {
    KeyDerivationStrategy::PBKDF2(900_000)
  }
}

impl TryFrom<Vec<u8>> for KeyDerivationStrategy {
  type Error = String;

  fn try_from(bytes: Vec<u8>) -> Result<Self, String> {
    match bytes[0] {
      0 => {
        let rounds_bytes = &bytes[1..];
        let rounds = usize::from_be_bytes(rounds_bytes.try_into().or(Err("Invalid rounds bytes"))?);
        Ok(KeyDerivationStrategy::PBKDF2(rounds))
      }
      _ => Err("Invalid key derivation strategy".to_string()),
    }
  }
}

impl From<KeyDerivationStrategy> for Vec<u8> {
  fn from(strategy: KeyDerivationStrategy) -> Self {
    match strategy {
      KeyDerivationStrategy::PBKDF2(rounds) => [vec![0u8], rounds.to_be_bytes().to_vec()].concat(),
    }
  }
}

impl PartialEq for KeyDerivationStrategy {
  fn eq(&self, other: &Self) -> bool {
    match (self, other) {
      (KeyDerivationStrategy::PBKDF2(rounds), KeyDerivationStrategy::PBKDF2(rounds2)) => {
        rounds == rounds2
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_key_derivation() {
    let password = "password".as_bytes();

    let key = Key::<32, 32>::new(password, KeyDerivationStrategy::PBKDF2(10_000));
    let key2 = Key::<32, 32>::with_salt(password, key.salt, KeyDerivationStrategy::PBKDF2(10_000));

    assert_eq!(key.pubk, key2.pubk);
  }

  #[test]
  fn test_key_derivation_with_different_salt() {
    let password = "password".as_bytes();

    let key = Key::<32, 32>::new(password, KeyDerivationStrategy::PBKDF2(10_000));
    let key2 = Key::<32, 32>::new(password, KeyDerivationStrategy::PBKDF2(10_000));

    assert_ne!(key.pubk, key2.pubk);
  }

  #[test]
  fn test_key_derivation_with_different_rounds() {
    let password = "password".as_bytes();

    let key = Key::<32, 32>::new(password, KeyDerivationStrategy::PBKDF2(10_000));
    let key2 = Key::<32, 32>::new(password, KeyDerivationStrategy::PBKDF2(11_000));

    assert_ne!(key.pubk, key2.pubk);
  }

  #[test]
  fn test_key_strategy_serialization_deserialization() {
    let strategy = KeyDerivationStrategy::PBKDF2(10_000);

    let serialized: Vec<u8> = strategy.clone().into();
    let deserialized = KeyDerivationStrategy::try_from(serialized).unwrap();

    assert_eq!(strategy, deserialized);
  }
}
