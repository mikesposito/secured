pub mod cipher;
pub mod encryption_key;
pub mod errors;

pub use cipher::{ChaCha20Poly1305Cipher, CipherKey, CipherNonce};
pub use encryption_key::EncryptionKey;
pub use errors::EnclaveError;

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

  /// The nonce used in the encryption process, 24 bytes long.
  nonce: [u8; 24],
}

impl<T> Enclave<T> {
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
    key: &CipherKey,
    plain_bytes: Vec<u8>,
  ) -> Result<Self, String> {
    let (encrypted_bytes, nonce) = ChaCha20Poly1305Cipher::encrypt(key, &plain_bytes)?;

    Ok(Enclave {
      metadata,
      encrypted_bytes: encrypted_bytes.into_boxed_slice(),
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
  pub fn decrypt(&self, key: &CipherKey) -> Result<Vec<u8>, String> {
    ChaCha20Poly1305Cipher::decrypt(key, &self.nonce, &self.encrypted_bytes)
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
    let encrypted_bytes = bytes[metadata_len as usize + 1..bytes.len() - 24].to_vec();
    let nonce = bytes[bytes.len() - 24..bytes.len()].to_vec();

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

#[cfg(test)]
mod tests {
  use super::*;

  mod from_plain_bytes {
    use super::*;

    #[test]
    fn it_should_create_enclave() {
      let key = ChaCha20Poly1305Cipher::new_key();
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();

      let safe = Enclave::from_plain_bytes("metadata", &key, bytes);

      assert!(safe.is_ok());
      assert_eq!(safe.unwrap().metadata, "metadata");
    }
  }

  mod decrypt {
    use super::*;

    #[test]
    fn it_should_decrypt_enclave() {
      let key = ChaCha20Poly1305Cipher::new_key();
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let safe = Enclave::from_plain_bytes("metadata", &key, bytes.clone()).unwrap();

      let decrypted_bytes = safe.decrypt(&key);

      assert!(decrypted_bytes.is_ok());
      assert_eq!(decrypted_bytes.unwrap(), bytes);
    }

    #[test]
    fn it_should_fail_with_wrong_key() {
      let key = ChaCha20Poly1305Cipher::new_key();
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let safe = Enclave::from_plain_bytes("metadata", &key, bytes).unwrap();

      let decrypted_bytes = safe.decrypt(&[0_u8; 32]);

      assert!(decrypted_bytes.is_err());
    }
  }
}
