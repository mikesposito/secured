use secured_cipher::KeyDerivationStrategy;

use crate::EnclaveError;

/// The `Encryptable` trait provides a common interface for encryption operations.
/// It is implemented by types that can be encrypted.
///
/// # Type Parameters
/// * `KEY_SIZE` - The size of the key to be used for encryption.
///
/// # Methods
/// * `encrypt` - Encrypts the type using a specified password and key derivation strategy.
/// * `encrypt_with_key` - Encrypts the type using a specified key.
/// * `encrypt_with_metadata` - Encrypts the type using a specified key and metadata.
pub trait Encryptable<const KEY_SIZE: usize> {
  fn encrypt(&self, password: String, strategy: KeyDerivationStrategy) -> Vec<u8>;

  fn encrypt_with_key(&self, key: [u8; KEY_SIZE]) -> Vec<u8>;

  fn encrypt_with_metadata<T>(&self, key: [u8; KEY_SIZE], metadata: T) -> Vec<u8>
  where
    T: From<Vec<u8>> + Into<Vec<u8>> + Clone;
}

/// The `Decryptable` trait provides a common interface for decryption operations.
/// It is implemented by types that can be decrypted.
///
/// # Type Parameters
/// * `KEY_SIZE` - The size of the key to be used for decryption.
///
/// # Methods
/// * `decrypt` - Decrypts the type using a specified password.
/// * `decrypt_with_key` - Decrypts the type using a specified key.
/// * `decrypt_with_metadata` - Decrypts the type using a specified key and metadata.
pub trait Decryptable<const KEY_SIZE: usize> {
  fn decrypt(&self, password: String) -> Result<Vec<u8>, EnclaveError>;

  fn decrypt_with_key(&self, key: [u8; KEY_SIZE]) -> Result<Vec<u8>, EnclaveError>;

  fn decrypt_with_metadata<T>(&self, key: [u8; KEY_SIZE]) -> Result<(Vec<u8>, T), EnclaveError>
  where
    T: TryFrom<Vec<u8>> + Into<Vec<u8>> + Clone;
}
