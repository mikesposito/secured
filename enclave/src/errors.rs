use std::fmt::{Display, Formatter, Result};

use secured_cipher::CipherError;

#[derive(Debug)]
pub enum EnclaveError {
  Serialization(String),
  Deserialization(String),
  Generic(String),
}

impl Display for EnclaveError {
  fn fmt(&self, f: &mut Formatter) -> Result {
    match self {
      EnclaveError::Serialization(message) => write!(f, "Unable to serialize safe > {}", message),
      EnclaveError::Deserialization(message) => {
        write!(f, "Unable to deserialize safe > {}", message)
      }
      EnclaveError::Generic(message) => write!(f, "Enclave error > {}", message),
    }
  }
}

impl From<CipherError> for EnclaveError {
  fn from(error: CipherError) -> Self {
    match error {
      CipherError::AuthenticationFailed => {
        EnclaveError::Deserialization("authentication failed".to_string())
      }
    }
  }
}

impl From<String> for EnclaveError {
  fn from(error: String) -> Self {
    EnclaveError::Generic(error)
  }
}
