use std::io::Read;

use secured_cipher::KeyDerivationStrategy;

use crate::EnclaveError;

#[derive(Debug, Clone, PartialEq)]
pub struct KeyMetadata {
  pub salt: [u8; 16],
  pub strategy: KeyDerivationStrategy,
}

impl From<KeyMetadata> for Vec<u8> {
  fn from(metadata: KeyMetadata) -> Self {
    let mut bytes = Vec::new();
    let strategy_bytes: Vec<u8> = metadata.strategy.into();

    bytes.extend(metadata.salt);
    bytes.extend(strategy_bytes);

    bytes
  }
}

impl TryFrom<Vec<u8>> for KeyMetadata {
  type Error = EnclaveError;

  fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
    let mut cursor = std::io::Cursor::new(bytes);

    let mut salt = [0u8; 16];
    cursor
      .read_exact(&mut salt)
      .or(Err(EnclaveError::Deserialization(
        "Failed to read salt".to_string(),
      )))?;

    let mut strategy_bytes = vec![];
    cursor
      .read_to_end(&mut strategy_bytes)
      .or(Err(EnclaveError::Deserialization(
        "Failed to read strategy bytes".to_string(),
      )))?;
    let strategy = KeyDerivationStrategy::try_from(strategy_bytes).or(Err(
      EnclaveError::Deserialization("Failed to parse key derivation strategy".to_string()),
    ))?;

    Ok(KeyMetadata { salt, strategy })
  }
}
