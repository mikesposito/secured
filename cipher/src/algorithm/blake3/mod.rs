use crate::algorithm::AlgorithmKeyInit;
use blake3::Hasher;

use super::{AEADAlgorithm, AlgorithmProcess};

pub struct Blake3Mac {
  key: [u8; 32],
}

impl Default for Blake3Mac {
  fn default() -> Self {
    Self { key: [0u8; 32] }
  }
}

impl AlgorithmKeyInit for Blake3Mac {
  fn init(&mut self, subkey: &[u8]) {
    let mut key = [0u8; 32];
    key.copy_from_slice(&subkey[..32]);
    self.key = key;
  }
}

impl AlgorithmProcess for Blake3Mac {
  fn process(&mut self, data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new_keyed(&self.key);
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
  }
}

impl AEADAlgorithm for Blake3Mac {}
