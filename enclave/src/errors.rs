use std::fmt::{Display, Formatter, Result};

pub enum EnclaveError {
  Serialization(String),
  Deserialization(String),
}

impl Display for EnclaveError {
  fn fmt(&self, f: &mut Formatter) -> Result {
    match self {
      EnclaveError::Serialization(message) => write!(f, "Unable to serialize safe > {}", message),
      EnclaveError::Deserialization(message) => write!(f, "Unable to deserialize safe > {}", message),
    }
  }
}
