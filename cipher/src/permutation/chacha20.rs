use crate::permutation::core::CHACHA20_NONCE_SIZE;

use super::core::{permute, xor_bytes, Block, CONSTANTS, STATE_WORDS};

use super::Permutation;

/// The `ChaCha20` struct represents the ChaCha20 stream cipher.
pub struct ChaCha20 {
  state: Block,
}

impl ChaCha20 {
  /// Constructs a new `ChaCha20` cipher instance.
  ///
  /// This function initializes the internal state of the cipher.
  ///
  /// # Returns
  /// A new instance of `ChaCha20`.
  pub fn new() -> Self {
    Self {
      state: [0u32; STATE_WORDS],
    }
  }

  /// Generates the next 64-byte keystream block from the ChaCha20 state.
  ///
  /// This function advances the ChaCha20 state and produces a keystream block based on the current state.
  /// It performs a permutation of the state, increments the block counter to ensure uniqueness for subsequent calls,
  /// and then serializes the permuted state into a 64-byte array.
  ///
  /// # Returns
  /// A 64-byte array representing the generated keystream block.
  ///
  /// # Panics
  /// Panics if the 32-bit block counter overflows, which would only happen after a very large
  /// number of blocks (2^32-1) have been processed with the same key-nonce combination.
  ///
  /// # Example
  /// ```
  /// use secured_cipher::{ChaCha20, Permutation};
  /// 
  /// let mut chacha20 = ChaCha20::new();
  /// chacha20.init(&[0_u8; 32], &[0_u8; 12]);
  /// 
  /// let keystream_block = chacha20.next_keystream();
  /// // `keystream_block` now contains the next 64 bytes of the keystream
  /// ```
  ///
  /// # Notes
  /// The keystream generated by this function is used to encrypt or decrypt data by XORing
  /// it with the plaintext or ciphertext. Each call to this function must produce a unique keystream block.
  /// This uniqueness is guaranteed by incrementing the internal block counter.
  pub fn next_keystream(&mut self) -> [u8; 64] {
    // Ensures the block counter has not overflowed
    assert!(self.state[12] != 0, "ChaCha20 counter overflow");

    // Initialize an array to hold the keystream
    let mut keystream = [0u8; 64];

    // Perform the ChaCha20 permutation on the current state
    let block = permute(&self.state);

    // Increment the block counter, wrapping around if it reaches its maximum value
    self.state[12] = self.state[12].wrapping_add(1);

    // Convert the 32-bit words from the permuted block into bytes and copy them into the keystream
    for (bytes, word) in keystream.chunks_exact_mut(4).zip(block) {
      bytes.copy_from_slice(&word.to_le_bytes());
    }

    // Return the generated 64-byte keystream block
    keystream
  }
}

impl Permutation for ChaCha20 {
  /// Initializes the ChaCha20 cipher with a given key and IV (initialization vector).
  ///
  /// This method sets up the cipher's internal state which includes the ChaCha20 constants, the provided key,
  /// a zeroed block counter, and the provided IV.
  ///
  /// # Arguments
  /// * `key` - A 256-bit key represented as 32 bytes.
  /// * `iv` - A 86-bit IV (nonce) represented as 12 bytes.
  fn init(&mut self, key: &[u8], iv: &[u8]) {
    // The key must be 256 bits (32 bytes) long, and the IV must be 64 bits (8 bytes) long.
    assert!(key.len() == 32);
    assert!(iv.len() == CHACHA20_NONCE_SIZE);

    // The first four words (16 bytes) of the state are set to the ChaCha20 constant.
    // This constant is the ASCII string "expand 32-byte k", used for creating the initial state.
    self.state[0..4].copy_from_slice(&CONSTANTS);

    // The next eight words (32 bytes) of the state are set to the encryption key.
    // The key is divided into 8 chunks, each containing 4 bytes (32 bits).
    // Each chunk is then converted from little-endian byte order to a u32 and stored in the state array.
    let key_chunks = key.chunks_exact(4);
    for (val, chunk) in self.state[4..12].iter_mut().zip(key_chunks) {
      *val = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // The block counter occupies the next word (13th positions) in the state.
    // In ChaCha20, this counter is used to make each block unique.
    self.state[12] = 1;

    // Here, we use the last 8-byte space of the block for the IV (initialization vector).
    let iv_chunks = iv.chunks_exact(4);
    for (val, chunk) in self.state[13..16].iter_mut().zip(iv_chunks) {
      *val = u32::from_le_bytes(chunk.try_into().unwrap());
    }
  }

  /// Processes input data using the ChaCha20 cipher algorithm.
  ///
  /// This function applies the ChaCha20 encryption or decryption process to the given input bytes.
  /// It works by generating a unique keystream for each 64-byte block of the input data and then
  /// applying an XOR operation between the data block and the keystream. This process is suitable
  /// for both encryption and decryption due to the reversible nature of the XOR operation.
  ///
  /// # Arguments
  /// * `bytes_in` - A slice of bytes representing the input data to be processed (either plaintext for encryption
  ///   or ciphertext for decryption).
  ///
  /// # Returns
  /// A `Vec<u8>` containing the processed data (encrypted or decrypted).
  ///
  /// # Behavior
  /// The function divides the input data into 64-byte blocks. For each block, it generates a unique
  /// keystream using the `next_keystream` method. Each block of the input data is then XORed with its
  /// corresponding keystream block. This method ensures that each block is encrypted or decrypted
  /// with a different keystream, which is essential for the security of the cipher.
  ///
  /// After processing all blocks, the function clears the internal state to prevent any residual
  /// sensitive data from remaining in memory.
  ///
  /// # Example
  /// ```
  /// use secured_cipher::{ChaCha20, Permutation};
  /// 
  /// let mut chacha20 = ChaCha20::new();
  /// chacha20.init(&[0_u8; 32], &[0_u8; 12]);
  /// 
  /// let data = b"some plaintext data"; // Data to be encrypted or decrypted
  /// let processed_data = chacha20.process(data);
  /// // `processed_data` now contains the encrypted or decrypted output
  /// ```
  ///
  /// # Notes
  /// It's important to use the same nonce and key for decrypting the data that were used for encryption.
  /// The output size will be equal to the input size, as ChaCha20 is a stream cipher.
  fn process(&mut self, bytes_in: &[u8]) -> Vec<u8> {
    // Clone the input bytes to prepare the output vector
    let mut out = bytes_in.to_owned();

    // Process each 64-byte block of the input data
    out.chunks_mut(64).for_each(|plain_chunk| {
      // Generate the keystream for the current block
      let keystream = self.next_keystream();
      // XOR the block with the keystream to perform encryption/decryption
      xor_bytes(plain_chunk, &keystream);
    });

    // Clear the internal state after processing to maintain security
    self.clear();

    // Return the processed data
    out.to_vec()
  }

  /// Clears the internal counter of the cipher.
  fn clear(&mut self) {
    // Reset the block counter
    self.state[12] = 1;
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
  const IV: [u8; CHACHA20_NONCE_SIZE] = [
    0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
  ];

  #[test]
  fn it_correctly_inits_the_chacha20_state() {
    let mut chacha20 = ChaCha20::new();
    chacha20.init(&KEY, &IV);

    assert_eq!(
      chacha20.state,
      [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000
      ]
    );
  }

  #[test]
  fn it_gets_the_first_keystream() {
    let mut chacha20 = ChaCha20::new();
    chacha20.init(&KEY, &IV);

    let block = chacha20.next_keystream();

    assert_eq!(
      block,
      [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4,
        0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9,
        0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8,
        0xa2, 0x50, 0x3c, 0x4e,
      ]
    );
  }

  #[test]
  fn it_encrypts_data() {
    let mut chacha20 = ChaCha20::new();
    chacha20.init(
      &KEY,
      &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
      ],
    );

    let encrypted_data = chacha20.process(&PLAINTEXT);

    assert_eq!(encrypted_data, CIPHERTEXT);
  }

  #[test]
  fn it_can_reverse_encryption() {
    let mut chacha20 = ChaCha20::new();
    chacha20.init(&[1u8; 32], &[2u8; CHACHA20_NONCE_SIZE]);
    let data = [0u8; 64];

    let encrypted_data = chacha20.process(&data);
    let decrypted_data = chacha20.process(&encrypted_data);

    assert_eq!(decrypted_data, data);
  }

  #[test]
  fn it_can_reverse_encryption_for_data_smaller_than_a_chunk() {
    let mut chacha20 = ChaCha20::new();
    chacha20.init(&[1u8; 32], &[2u8; CHACHA20_NONCE_SIZE]);
    let data = [0u8; 1];

    let encrypted_data = chacha20.process(&data);
    let decrypted_data = chacha20.process(&encrypted_data);

    assert_eq!(decrypted_data, data);
  }
}
