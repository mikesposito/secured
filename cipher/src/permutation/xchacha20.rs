use std::sync::Arc;

use crate::permutation::core::XCHACHA20_NONCE_SIZE;

use super::core::{
  seek_keystream, to_u32_slice, u32_to_u8_vec, xor, CONSTANTS, PARALLEL_BLOCKS, STATE_WORDS,
  WORDS_PER_THREAD,
};

use super::Permutation;

use rayon::prelude::*;

/// The `XChaCha20` struct represents the XChaCha20 stream cipher.
pub struct XChaCha20 {
  state: [u32; STATE_WORDS],
}

impl XChaCha20 {
  /// Constructs a new `XChaCha20` cipher instance.
  ///
  /// This function initializes the internal state of the cipher.
  ///
  /// # Returns
  /// A new instance of `XChaCha20`.
  pub fn new() -> Self {
    Self {
      state: [0u32; STATE_WORDS],
    }
  }
}

impl Permutation for XChaCha20 {
  /// Initializes the XChaCha20 cipher with a given key and IV (initialization vector).
  ///
  /// This method sets up the cipher's internal state which includes the XChaCha20 constants, the provided key,
  /// a zeroed block counter, and the provided IV.
  ///
  /// # Arguments
  /// * `key` - A 256-bit key represented as 32 bytes.
  /// * `iv` - A 96-bit IV (nonce) represented as 12 bytes.
  fn init(&mut self, key: &[u8], iv: &[u8]) {
    // The key must be 256 bits (32 bytes) long, and the IV must be 96 bits (12 bytes) long.
    assert!(key.len() == 32);
    assert!(iv.len() == XCHACHA20_NONCE_SIZE);

    // The first four words (16 bytes) of the state are set to the XChaCha20 constant.
    // This constant is the ASCII string "expand 32-byte k", used for creating the initial state.
    self.state[0..4].copy_from_slice(&CONSTANTS);

    // The next eight words (32 bytes) of the state are set to the encryption key.
    // The key is divided into 8 chunks, each containing 4 bytes (32 bits).
    // Each chunk is then converted from little-endian byte order to a u32 and stored in the state array.
    let key_chunks = key.chunks_exact(4);
    for (val, chunk) in self.state[4..12].iter_mut().zip(key_chunks) {
      *val = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // The block counter occupies the next one word (13th position) in the state.
    // In XChaCha20, this counter is used to make each block unique.
    self.state[12] = 0;

    // Here, we use the last 12-byte space of the block for the IV (initialization vector).
    let iv_chunks = iv.chunks_exact(4);
    for (val, chunk) in self.state[13..16].iter_mut().zip(iv_chunks) {
      *val = u32::from_le_bytes(chunk.try_into().unwrap());
    }
  }

  /// Processes the input data with the XChaCha20 cipher.
  ///
  /// This method encrypts or decrypts the input data by XORing it with the keystream generated from the cipher's internal state.
  /// It is suitable for both encryption and decryption due to the XOR operation's reversible nature.
  ///
  /// # Arguments
  /// * `bytes_in` - A slice of bytes to be processed (encrypted or decrypted).
  ///
  /// # Returns
  /// A vector of bytes containing the processed (encrypted or decrypted) data.
  fn process(&mut self, bytes_in: &[u8]) -> Vec<u8> {
    // Prepare the output vector of 32-bit words from the input
    let mut out: Vec<u32> = to_u32_slice(bytes_in);
    // Wrap the state in an Arc to allow for parallel processing
    let arc_state = Arc::new(self.state);

    // Process each chunk of 8 blocks in parallel
    out
      .par_chunks_mut(WORDS_PER_THREAD)
      .enumerate()
      .for_each(|(i, blocks_chunk)| {
        blocks_chunk
          .chunks_mut(STATE_WORDS)
          .enumerate()
          .for_each(|(j, block)| {
            // Cipher each 64-byte block in the chunk
            let chunk_keystream = seek_keystream(&arc_state, (i * PARALLEL_BLOCKS + j) as u64, 1);
            xor(block, &chunk_keystream);
          });
      });

    // Clear the keystream
    self.clear();

    // Convert the output to a byte vector
    let mut bytes_out = u32_to_u8_vec(&out);
    // Truncate the output to the length of the input,
    // as the output may contain extra bytes if the input length is not a multiple of 64
    bytes_out.truncate(bytes_in.len());
    bytes_out
  }

  /// Clears the internal counter of the cipher.
  fn clear(&mut self) {
    // Reset the block counter
    self.state[12] = 0;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const PLAINTEXT: [u8; 114] = [
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e,
  ];
  const KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ];
  const CIPHERTEXT: [u8; 114] = [
    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
    0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
    0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
    0x87, 0x4d,
  ];
  const IV: [u8; XCHACHA20_NONCE_SIZE] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];

  #[test]
  fn it_constructs_an_unencrypted_chacha_block() {
    let mut xchacha20 = XChaCha20::new();
    xchacha20.init(&KEY, &IV);

    assert_eq!(xchacha20.state.len(), 16);
    assert_eq!(xchacha20.state[0..4], CONSTANTS);
    assert_eq!(
      xchacha20.state[4..12],
      [67305985, 134678021, 202050057, 269422093, 336794129, 404166165, 471538201, 538910237]
    );
    assert_eq!(xchacha20.state[12], 0);
    assert_eq!(xchacha20.state[13], 67305985);
    assert_eq!(xchacha20.state[14], 134678021);
    assert_eq!(xchacha20.state[15], 218893066);
  }

  #[test]
  fn it_encrypts_data() {
    let mut xchacha20 = XChaCha20::new();
    xchacha20.init(&KEY, &IV);

    let encrypted_data = xchacha20.process(&PLAINTEXT);

    assert_eq!(encrypted_data, CIPHERTEXT);
  }

  #[test]
  fn it_can_reverse_encryption() {
    let mut xchacha20 = XChaCha20::new();
    xchacha20.init(&[1u8; 32], &[2u8; XCHACHA20_NONCE_SIZE]);
    let data = [0u8; 64];

    let encrypted_data = xchacha20.process(&data);
    let decrypted_data = xchacha20.process(&encrypted_data);

    assert_eq!(decrypted_data, data);
  }

  #[test]
  fn it_can_reverse_encryption_for_data_smaller_than_a_chunk() {
    let mut xchacha20 = XChaCha20::new();
    xchacha20.init(&[1u8; 32], &[2u8; XCHACHA20_NONCE_SIZE]);
    let data = [0u8; 1];

    let encrypted_data = xchacha20.process(&data);
    let decrypted_data = xchacha20.process(&encrypted_data);

    assert_eq!(decrypted_data, data);
  }
}
