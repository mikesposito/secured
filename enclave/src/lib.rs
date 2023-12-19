pub mod errors;
pub mod traits;

pub use errors::EnclaveError;
pub use traits::{Decryptable, Encryptable};

pub use secured_cipher::{
  algorithm::chacha20::CHACHA20_NONCE_SIZE, random_bytes, Cipher, Key, KeyDerivationStrategy,
  SignedEnvelope,
};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = CHACHA20_NONCE_SIZE;

/// `Enclave` acts as a container for encrypted data, including metadata and the encrypted content itself.
///
/// Metadata is unencrypted and can be used to store information about the data,
/// while the actual data is securely encrypted.
///
/// # Type Parameters
/// * `T`: The type of metadata associated with the encrypted data.
#[derive(Debug, Clone)]
pub struct Enclave<T> {
  /// Metadata associated with the encrypted data.
  pub metadata: T,

  /// The encrypted data.
  encrypted_bytes: Box<[u8]>,

  /// The nonce used in the encryption process, 8 bytes long (ChaCha20).
  nonce: [u8; NONCE_SIZE],
}

impl<T> Enclave<T>
where
  T: TryFrom<Vec<u8>> + Into<Vec<u8>> + Clone,
{
  /// Creates a new `Enclave` instance from unencrypted data.
  ///
  /// # Arguments
  /// * `metadata`: The metadata to be associated with the encrypted data.
  /// * `key`: A 32-byte cipher key used for encryption.
  /// * `plain_bytes`: The data to be encrypted.
  ///
  /// # Returns
  /// A `Result` containing the newly created `Enclave` instance, or an error string if encryption fails.
  pub fn from_plain_bytes(
    metadata: T,
    key: [u8; KEY_SIZE],
    plain_bytes: Vec<u8>,
  ) -> Result<Self, String> {
    let nonce = random_bytes::<NONCE_SIZE>();
    let mut cipher = Cipher::default();
    cipher.init(&key, &nonce);

    let encrypted_bytes = cipher.encrypt(&plain_bytes);
    let envelope: Vec<u8> = cipher
      .sign(&metadata.clone().into(), &encrypted_bytes)
      .into();

    Ok(Enclave {
      metadata,
      encrypted_bytes: envelope.into_boxed_slice(),
      nonce,
    })
  }

  /// Decrypts the contents of the enclave using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for decryption.
  ///
  /// # Returns
  /// A `Result` containing the decrypted data as a vector of bytes, or an error string if decryption fails.
  pub fn decrypt(&self, key: [u8; KEY_SIZE]) -> Result<Vec<u8>, EnclaveError> {
    let envelope = SignedEnvelope::from(self.encrypted_bytes.to_vec());

    Ok(
      Cipher::default()
        .init(&key, &self.nonce)
        .decrypt_and_verify(&envelope)?,
    )
  }
}

impl<T> From<Enclave<T>> for Vec<u8>
where
  T: TryFrom<Vec<u8>> + Into<Vec<u8>>,
{
  /// Serializes an `Enclave` instance into a byte vector.
  ///
  /// # Arguments
  /// * `enclave`: The `Enclave` instance to be serialized.
  ///
  /// # Returns
  /// A `Vec<u8>` representing the serialized enclave.
  fn from(enclave: Enclave<T>) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];
    let metadata_bytes = enclave.metadata.into();

    bytes.append(&mut vec![u8::try_from(metadata_bytes.len()).unwrap()]);
    bytes.append(&mut metadata_bytes.into());
    bytes.append(&mut enclave.encrypted_bytes.into());
    bytes.append(&mut enclave.nonce.to_vec());

    bytes
  }
}

impl<T> TryFrom<Vec<u8>> for Enclave<T>
where
  T: TryFrom<Vec<u8>> + Into<Vec<u8>>,
{
  type Error = EnclaveError;

  /// Deserializes a byte vector into an `Enclave` instance.
  ///
  /// # Arguments
  /// * `bytes`: The byte vector representing the serialized enclave.
  ///
  /// # Returns
  /// A `Result` containing the deserialized `Enclave` instance, or an `EnclaveError` if deserialization fails.
  fn try_from(bytes: Vec<u8>) -> Result<Self, EnclaveError> {
    let metadata_len = bytes[0];
    let metadata = T::try_from(bytes[1..metadata_len as usize + 1].to_vec()).or(Err(
      EnclaveError::Deserialization("error deserializing metadata".to_string()),
    ))?;
    let encrypted_bytes = bytes[metadata_len as usize + 1..bytes.len() - NONCE_SIZE].to_vec();
    let nonce = bytes[bytes.len() - NONCE_SIZE..bytes.len()].to_vec();

    Ok(Enclave {
      metadata,
      encrypted_bytes: encrypted_bytes.into_boxed_slice(),
      nonce: nonce.try_into().or(Err(EnclaveError::Deserialization(
        "unexpected bytes length".to_string(),
      )))?,
    })
  }
}

impl<T> PartialEq for Enclave<T>
where
  T: PartialEq + TryFrom<Vec<u8>> + Into<Vec<u8>>,
{
  /// Compares two `Enclave` instances for equality.
  ///
  /// # Arguments
  /// * `other`: Another `Enclave` instance to compare with.
  ///
  /// # Returns
  /// `true` if both `Enclave` instances are equal, `false` otherwise.
  fn eq(&self, other: &Self) -> bool {
    self.metadata == other.metadata
      && self.encrypted_bytes == other.encrypted_bytes
      && self.nonce == other.nonce
  }
}

impl Encryptable<KEY_SIZE> for Vec<u8> {
  /// Encrypts a vector of bytes using a provided password.
  ///
  /// # Arguments
  /// * `password`: The password to use for key derivation.
  /// * `strategy`: The key derivation strategy to use.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt(&self, password: String, strategy: KeyDerivationStrategy) -> Vec<u8> {
    let key: Key<32, 16> = Key::new(password.as_bytes(), strategy.clone());
    let enclave = Enclave::from_plain_bytes(vec![], key.pubk, self.clone()).unwrap();

    [enclave.into(), key.salt.to_vec(), strategy.into()].concat()
  }

  /// Encrypts a vector of bytes using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_key(&self, key: &Key<32, 16>) -> Vec<u8> {
    let enclave = Enclave::from_plain_bytes(vec![], key.pubk, self.clone()).unwrap();
    [
      enclave.into(),
      key.salt.to_vec(),
      key.strategy.clone().into(),
    ]
    .concat()
  }

  /// Encrypts a vector of bytes using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_raw_key(&self, key: [u8; KEY_SIZE]) -> Vec<u8> {
    let enclave = Enclave::from_plain_bytes(vec![], key, self.clone()).unwrap();
    enclave.into()
  }

  /// Encrypts a vector of bytes using a provided key and metadata.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  /// * `metadata`: The metadata to be associated with the encrypted data.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_metadata<M>(&self, key: [u8; KEY_SIZE], metadata: M) -> Vec<u8>
  where
    M: From<Vec<u8>> + Into<Vec<u8>> + Clone,
  {
    let enclave = Enclave::from_plain_bytes(metadata, key, self.clone()).unwrap();
    enclave.into()
  }
}

impl Decryptable<KEY_SIZE> for Vec<u8> {
  /// Decrypts a slice of bytes using a provided password.
  ///
  /// # Arguments
  /// * `password`: The password to use for decryption.
  ///
  /// # Returns
  /// A `Result` containing the decrypted data as a vector of bytes, or an error string if decryption fails.
  fn decrypt(&self, password: String) -> Result<Vec<u8>, EnclaveError> {
    let strategy = KeyDerivationStrategy::try_from(self[self.len() - 9..self.len()].to_vec())?;
    let salt: [u8; 16] = self[self.len() - 25..self.len() - 9].try_into().unwrap();
    let key = Key::<KEY_SIZE, 16>::with_salt(password.as_bytes(), salt, strategy);

    let enclave = Enclave::<Vec<u8>>::try_from(self[..self.len() - 25].to_vec())?;

    enclave.decrypt(key.pubk)
  }

  /// Decrypts a slice of bytes using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for decryption.
  ///
  /// # Returns
  /// A `Result` containing the decrypted data as a vector of bytes, or an error string if decryption fails.
  fn decrypt_with_key(&self, key: [u8; KEY_SIZE]) -> Result<Vec<u8>, EnclaveError> {
    let enclave = Enclave::<Vec<u8>>::try_from(self.clone())?;
    enclave.decrypt(key)
  }

  /// Decrypts a slice of bytes using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for decryption.
  ///
  /// # Returns
  /// A `Result` containing the decrypted data as a vector of bytes, or an error string if decryption fails.
  fn decrypt_with_metadata<M>(&self, key: [u8; KEY_SIZE]) -> Result<(Vec<u8>, M), EnclaveError>
  where
    M: TryFrom<Vec<u8>> + Into<Vec<u8>> + Clone,
  {
    let enclave = Enclave::<M>::try_from(self.clone())?;
    let decrypted_bytes = enclave.decrypt(key)?;
    Ok((decrypted_bytes, enclave.metadata))
  }
}

impl Decryptable<KEY_SIZE> for &[u8] {
  /// Decrypts a slice of bytes using a provided password.
  ///
  /// # Arguments
  /// * `password`: The password to use for decryption.
  ///
  /// # Returns
  /// A `Result` containing the decrypted data as a vector of bytes, or an error string if decryption fails.
  fn decrypt(&self, password: String) -> Result<Vec<u8>, EnclaveError> {
    self.to_vec().decrypt(password)
  }

  /// Decrypts a slice of bytes using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for decryption.
  ///
  /// # Returns
  /// A `Result` containing the decrypted data as a vector of bytes, or an error string if decryption fails.
  fn decrypt_with_key(&self, key: [u8; KEY_SIZE]) -> Result<Vec<u8>, EnclaveError> {
    self.to_vec().decrypt_with_key(key)
  }

  /// Decrypts a slice of bytes using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for decryption.
  ///
  /// # Returns
  /// A `Result` containing the decrypted data as a vector of bytes, or an error string if decryption fails.
  fn decrypt_with_metadata<M>(&self, key: [u8; KEY_SIZE]) -> Result<(Vec<u8>, M), EnclaveError>
  where
    M: TryFrom<Vec<u8>> + Into<Vec<u8>> + Clone,
  {
    self.to_vec().decrypt_with_metadata(key)
  }
}

impl Encryptable<KEY_SIZE> for &[u8] {
  /// Encrypts a slice of bytes using a provided password.
  ///
  /// # Arguments
  /// * `password`: The password to use for key derivation.
  /// * `strategy`: The key derivation strategy to use.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt(&self, password: String, strategy: KeyDerivationStrategy) -> Vec<u8> {
    self.to_vec().encrypt(password, strategy)
  }

  /// Encrypts a slice of bytes using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_key(&self, key: &Key<32, 16>) -> Vec<u8> {
    self.to_vec().encrypt_with_key(key)
  }

  /// Encrypts a slice of bytes using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_raw_key(&self, key: [u8; KEY_SIZE]) -> Vec<u8> {
    self.to_vec().encrypt_with_raw_key(key)
  }

  /// Encrypts a slice of bytes using a provided key and metadata.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  /// * `metadata`: The metadata to be associated with the encrypted data.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_metadata<M>(&self, key: [u8; KEY_SIZE], metadata: M) -> Vec<u8>
  where
    M: From<Vec<u8>> + Into<Vec<u8>> + Clone,
  {
    self.to_vec().encrypt_with_metadata(key, metadata)
  }
}

impl Encryptable<KEY_SIZE> for String {
  /// Encrypts a string using a provided password.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  /// * `strategy`: The key derivation strategy to use.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt(&self, password: String, strategy: KeyDerivationStrategy) -> Vec<u8> {
    self.as_bytes().to_vec().encrypt(password, strategy)
  }

  /// Encrypts a String using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_key(&self, key: &Key<32, 16>) -> Vec<u8> {
    self.as_bytes().to_vec().encrypt_with_key(key)
  }

  /// Encrypts a String using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_raw_key(&self, key: [u8; KEY_SIZE]) -> Vec<u8> {
    self.as_bytes().to_vec().encrypt_with_raw_key(key)
  }

  /// Encrypts a String using a provided key and metadata.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  /// * `metadata`: The metadata to be associated with the encrypted data.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_metadata<M>(&self, key: [u8; KEY_SIZE], metadata: M) -> Vec<u8>
  where
    M: From<Vec<u8>> + Into<Vec<u8>> + Clone,
  {
    self
      .as_bytes()
      .to_vec()
      .encrypt_with_metadata(key, metadata)
  }
}

impl Encryptable<KEY_SIZE> for &str {
  /// Encrypts a &str using a provided password.
  ///
  /// # Arguments
  /// * `password`: The password to use for key derivation.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt(&self, password: String, strategy: KeyDerivationStrategy) -> Vec<u8> {
    self.as_bytes().to_vec().encrypt(password, strategy)
  }

  /// Encrypts a string using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_key(&self, key: &Key<32, 16>) -> Vec<u8> {
    self.as_bytes().to_vec().encrypt_with_key(key)
  }

  /// Encrypts a string using a provided key.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_raw_key(&self, key: [u8; KEY_SIZE]) -> Vec<u8> {
    self.as_bytes().to_vec().encrypt_with_raw_key(key)
  }

  /// Encrypts an &str using a provided key and metadata.
  ///
  /// # Arguments
  /// * `key`: The 32-byte cipher key used for encryption.
  /// * `metadata`: The metadata to be associated with the encrypted data.
  ///
  /// # Returns
  /// A `Vec<u8>` containing the encrypted data.
  fn encrypt_with_metadata<M>(&self, key: [u8; KEY_SIZE], metadata: M) -> Vec<u8>
  where
    M: From<Vec<u8>> + Into<Vec<u8>> + Clone,
  {
    self
      .as_bytes()
      .to_vec()
      .encrypt_with_metadata(key, metadata)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  mod from_plain_bytes {
    use super::*;

    #[test]
    fn it_should_create_enclave() {
      let key = [0u8; KEY_SIZE];
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();

      let safe = Enclave::from_plain_bytes(b"metadata".to_owned(), key, bytes);

      assert!(safe.is_ok());
      assert_eq!(safe.unwrap().metadata, b"metadata".to_owned());
    }
  }

  mod decrypt {
    use super::*;

    #[test]
    fn it_should_decrypt_enclave() {
      let key = [0u8; KEY_SIZE];
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let safe = Enclave::from_plain_bytes(b"metadata".to_vec(), key, bytes.clone()).unwrap();

      let decrypted_bytes = safe.decrypt(key);

      assert!(decrypted_bytes.is_ok());
      assert_eq!(decrypted_bytes.unwrap(), bytes);
    }

    #[test]
    fn it_should_fail_with_wrong_key() {
      let key = [0u8; KEY_SIZE];
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let safe = Enclave::from_plain_bytes(b"metadata".to_vec(), key, bytes.clone()).unwrap();
      let wrong_key = [1u8; KEY_SIZE];

      let decrypted_bytes = safe.decrypt(wrong_key);

      assert!(!decrypted_bytes.is_ok());
    }

    #[test]
    fn it_should_serialize_and_deserialize_to_bytes() {
      let key = [0u8; KEY_SIZE];
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let enclave = Enclave::from_plain_bytes([0_u8, 1_u8], key, bytes.clone()).unwrap();

      let serialized: Vec<u8> = enclave.clone().into();
      let deserialized = Enclave::try_from(serialized).unwrap();

      assert_eq!(enclave, deserialized);
    }

    #[test]
    fn vec_u8_should_be_encryptable_and_decryptable_with_password() {
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let password = "my password".to_string();

      // Using a low number of iterations here because tests are slow
      let encrypted_bytes = bytes.encrypt(password.clone(), KeyDerivationStrategy::PBKDF2(10_000));
      let decrypted_bytes = encrypted_bytes.decrypt(password);

      assert!(decrypted_bytes.is_ok());
      assert_eq!(decrypted_bytes.unwrap(), bytes);
    }

    #[test]
    fn vec_u8_should_be_encryptable_and_decryptable_with_key() {
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let key = [0u8; KEY_SIZE];

      let encrypted_bytes = bytes.encrypt_with_raw_key(key);
      let decrypted_bytes = encrypted_bytes.decrypt_with_key(key);

      assert!(decrypted_bytes.is_ok());
      assert_eq!(decrypted_bytes.unwrap(), bytes);
    }

    #[test]
    fn vec_u8_should_be_encryptable_and_decryptable_with_metadata() {
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let key = [0u8; KEY_SIZE];

      let encrypted_bytes = bytes.encrypt_with_metadata(key, b"metadata".to_vec());
      let decrypted_bytes = encrypted_bytes.decrypt_with_metadata::<Vec<u8>>(key);

      assert!(decrypted_bytes.is_ok());
      assert_eq!(decrypted_bytes.unwrap(), (bytes, b"metadata".to_vec()));
    }

    #[test]
    fn strings_should_be_encryptable_and_decryptable_with_password() {
      let string = "my string".to_string();
      let password = "my password".to_string();

      // Using a low number of iterations here because tests are slow
      let encrypted_bytes = string.encrypt(password.clone(), KeyDerivationStrategy::PBKDF2(10_000));
      let decrypted_bytes = encrypted_bytes.decrypt(password);

      assert!(decrypted_bytes.is_ok());
      assert_eq!(decrypted_bytes.unwrap(), string.as_bytes());
    }
  }
}
