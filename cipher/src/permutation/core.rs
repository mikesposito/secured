//! ChaCha20 Cryptographic Algorithm Implementation
//!
//! This module provides an implementation of the ChaCha20 stream cipher, 
//! as specified in RFC 7539 by the Internet Engineering Task Force (IETF). 
//! The implementation includes constants, state management, encryption/decryption functions, 
//! and utilities for data transformation relevant to the ChaCha20 algorithm.
//!
//! The constants and logic, as well as the test vectors used in this module, 
//! are based on and verifiable against the specifications detailed in the IETF paper: 
//! "ChaCha20 and Poly1305 for IETF Protocols" (RFC 7539). 
//! This can be accessed at https://datatracker.ietf.org/doc/html/rfc7539.
//!
//! The module is designed to be compliant with the RFC 7539 standard, ensuring reliability
//! and correctness of the cryptographic operations as per the established IETF guidelines.

/// Constants for the ChaCha20 algorithm.
/// These four 32-bit words represent the ASCII encoding of "expand 32-byte k",
/// used in the state initialization of the ChaCha20 block.
pub const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Number of 32-bit words in the ChaCha state.
/// The ChaCha20 state consists of 16 words, each of which is 32 bits long.
pub const STATE_WORDS: usize = 16;

/// Number of ChaCha20 rounds.
/// This constant defines how many rounds of the main ChaCha20 algorithm will be executed.
/// The standard number of rounds is 20.
pub const ROUNDS: usize = 10;

/// Size of the ChaCha20 nonce in bytes.
/// The nonce is a 64-bit (8 bytes) value used to make each block unique.
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// Size of the XChaCha20 nonce in bytes.
/// The nonce is a 128-bit (16 bytes) value used to make each block unique.
pub const XCHACHA20_NONCE_SIZE: usize = 16;

/// Size of the key in bytes.
/// The key is a 256-bit (32 bytes) value used for encryption and decryption.
pub const KEY_SIZE: usize = 32;

/// The array of words representing a ChaCha20 block.
pub type Block = [u32; STATE_WORDS];

/// Performs the quarter round operation on the state.
///
/// This operation modifies four words in the state as per the ChaCha20 algorithm's quarter round rules.
/// It involves a series of addition, XOR, and rotation operations to mix the input words.
///
/// # Arguments
/// * `a`, `b`, `c`, `d` - Indices of the state words to be modified.
/// * `state` - A mutable reference to the 512-bit state array.
pub fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut Block) {
  state[a] = state[a].wrapping_add(state[b]);
  state[d] ^= state[a];
  state[d] = state[d].rotate_left(16);

  state[c] = state[c].wrapping_add(state[d]);
  state[b] ^= state[c];
  state[b] = state[b].rotate_left(12);

  state[a] = state[a].wrapping_add(state[b]);
  state[d] ^= state[a];
  state[d] = state[d].rotate_left(8);

  state[c] = state[c].wrapping_add(state[d]);
  state[b] ^= state[c];
  state[b] = state[b].rotate_left(7);
}

/// Runs the ChaCha20 permutation on the provided state.
pub fn permute(state: &Block) -> Block {
  let mut block = state.clone();

  // The ChaCha20 permutation consists of 20 rounds of quarter round operations.
  run_rounds(&mut block);

  // The original ChaCha20 algorithm adds the original state to the output of the rounds.
  for (s1, s0) in block.iter_mut().zip(state.iter()) {
    *s1 = s1.wrapping_add(*s0);
  }

  block
}

/// Runs the ChaCha20 rounds on the provided state.
/// This function modifies the state in place.
pub fn run_rounds(state: &mut Block) {
  for _ in 0..ROUNDS {
    // Odd rounds
    quarter_round(0, 4, 8, 12, state);
    quarter_round(1, 5, 9, 13, state);
    quarter_round(2, 6, 10, 14, state);
    quarter_round(3, 7, 11, 15, state);
    // Even rounds
    quarter_round(0, 5, 10, 15, state);
    quarter_round(1, 6, 11, 12, state);
    quarter_round(2, 7, 8, 13, state);
    quarter_round(3, 4, 9, 14, state);
  }
}

/// XORs two 512-bit state arrays.
/// This function modifies the first array in place.
///
/// # Arguments
/// * `a` - A mutable reference to the first state array.
/// * `b` - A reference to the second state array.
///
/// # Panics
/// Panics if the two arrays are not of equal length.
pub fn xor_bytes(left: &mut [u8], right: &[u8]) {
  assert!(
    right.len() >= left.len(),
    "The left array can't be XORed completely with the right array"
  );
  left
    .iter_mut()
    .zip(right.iter())
    .for_each(|(left, right)| *left ^= *right);
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn it_should_do_the_quarter_round() {
    let mut state: Block = [
      0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
      0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
      0x2098d9d6, 0x91dbd320,
    ];

    quarter_round(2, 7, 8, 13, &mut state);

    assert_eq!(
      state,
      [
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
        0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
        0x2098d9d6, 0x91dbd320,
      ]
    );
  }

  #[test]
  fn it_runs_all_the_quarter_rounds() {
    let mut state: Block = [
      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
      0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
      0x4a000000, 0x00000000,
    ];

    run_rounds(&mut state);

    assert_eq!(
      state,
      [
        0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, 0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc,
        0x3f5ec7b7, 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd, 0xd19c12b4, 0xb04e16de,
        0x9e83d0cb, 0x4e3c50a2,
      ]
    );
  }

  #[test]
  fn it_executes_the_chacha20_permutation() {
    let state: Block = [
      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
      0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
      0x4a000000, 0x00000000,
    ];

    let result = permute(&state);

    assert_eq!(
      result,
      [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
        0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
        0xe883d0cb, 0x4e3c50a2,
      ]
    );
  }
}
