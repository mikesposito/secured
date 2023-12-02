pub mod errors;

pub use errors::EnclaveError;
use secured_cipher::{
  permutation::core::{KEY_SIZE, XCHACHA20_NONCE_SIZE},
  random_bytes, Cipher,
};

const NONCE_SIZE: usize = XCHACHA20_NONCE_SIZE;

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
    key: [u8; KEY_SIZE],
    plain_bytes: Vec<u8>,
  ) -> Result<Self, String> {
    let nonce = random_bytes::<NONCE_SIZE>();
    let encrypted_bytes = Cipher::default().init(&key, &nonce).encrypt(&plain_bytes);

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
  pub fn decrypt(&self, key: [u8; KEY_SIZE]) -> Result<Vec<u8>, String> {
    Ok(
      Cipher::default()
        .init(&key, &self.nonce)
        .decrypt(&self.encrypted_bytes),
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

#[cfg(test)]
mod tests {
  use super::*;
  use secured_cipher::Key;

  mod from_plain_bytes {
    use super::*;

    #[test]
    fn it_should_create_enclave() {
      let key: Key<32, 16> = Key::new(b"my password", 10_000);
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();

      let safe = Enclave::from_plain_bytes("metadata", key.pubk, bytes);

      assert!(safe.is_ok());
      assert_eq!(safe.unwrap().metadata, "metadata");
    }
  }

  mod decrypt {
    use super::*;

    #[test]
    fn it_should_decrypt_enclave() {
      let key: Key<32, 16> = Key::new(b"my password", 10_000);
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let safe = Enclave::from_plain_bytes("metadata", key.pubk, bytes.clone()).unwrap();

      let decrypted_bytes = safe.decrypt(key.pubk);

      assert!(decrypted_bytes.is_ok());
      assert_eq!(decrypted_bytes.unwrap(), bytes);
    }

    #[test]
    fn it_should_fail_with_wrong_key() {
      let key: Key<32, 16> = Key::new(b"my password", 10_000);
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let safe = Enclave::from_plain_bytes("metadata", key.pubk, bytes.clone()).unwrap();
      let wrong_key: Key<32, 16> = Key::new(b"my wrong password", 10_000);

      let decrypted_bytes = safe.decrypt(wrong_key.pubk).unwrap();

      assert_ne!(decrypted_bytes, bytes);
    }

    #[test]
    fn it_should_serialize_and_deserialize_to_bytes() {
      let key: Key<32, 16> = Key::new(b"my password", 10_000);
      let bytes = [0u8, 1u8, 2u8, 3u8, 4u8].to_vec();
      let enclave = Enclave::from_plain_bytes([0_u8, 1_u8], key.pubk, bytes.clone()).unwrap();

      let serialized: Vec<u8> = enclave.clone().into();
      let deserialized = Enclave::try_from(serialized).unwrap();

      assert_eq!(enclave, deserialized);
    }
  }
}
