pub mod core;

use core::{
  compress_schedule, init_working_variables, pad, prepare_schedule, update_hash, Sha256Hash,
  INITIAL_HASH,
};

use super::Hasher;

pub struct Sha256 {
  hash: Sha256Hash,
}

impl Default for Sha256 {
  fn default() -> Self {
    Self { hash: INITIAL_HASH }
  }
}

impl Sha256 {
  /// Resets the hash to its initial state.
  pub fn reset(&mut self) {
    self.hash = INITIAL_HASH;
  }

  pub fn process_block(&mut self, block: &[u32; 16]) {
    let schedule = prepare_schedule(block);
    let mut v = init_working_variables(&self.hash);

    // Perform the main hash computation loop.
    compress_schedule(&schedule, &mut v);

    // Update the hash with the computed values.
    update_hash(&mut self.hash, &v);
  }
}

impl Hasher for Sha256 {
  fn update(&mut self, data: &[u8]) {
    pad(data).chunks(64).for_each(|chunk| {
      let mut block = [0u32; 16];
      for (i, word) in chunk.chunks(4).enumerate() {
        let mut bytes = [0u8; 4];
        for (j, &byte) in word.iter().enumerate() {
          bytes[j] = byte;
        }
        block[i] = u32::from_be_bytes(bytes);
      }
      self.process_block(&block);
    });
  }

  fn finalize(&self) -> Vec<u8> {
    let mut result = Vec::with_capacity(32);
    for &word in &self.hash {
      result.extend_from_slice(&word.to_be_bytes());
    }
    result
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn it_should_process_sha256() {
    let mut hasher = Sha256::default();
    let data = b"abc";

    hasher.update(data);

    assert_eq!(
      hasher.finalize(),
      [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad
      ]
    );
  }
}
