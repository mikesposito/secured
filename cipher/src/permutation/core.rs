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

/// Calculates the `h` values for Poly1305.
///
/// This function takes a block of data and the high bit (hibit) and calculates
/// the `h` values as per the Poly1305 algorithm.
///
/// # Arguments
/// * `block` - A reference to a 16-byte array representing the data block.
/// * `hibit` - The high bit, used in the calculation of `h4`.
///
/// # Returns
/// A tuple of five `u32` values representing the calculated `h` values.
pub fn calculate_poly1305_h_values(block: &[u8; 16], hibit: u32) -> (u32, u32, u32, u32, u32) {
  let h0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
  let h1 = u32::from_le_bytes(block[3..7].try_into().unwrap()) >> 2;
  let h2 = u32::from_le_bytes(block[6..10].try_into().unwrap()) >> 4;
  let h3 = u32::from_le_bytes(block[9..13].try_into().unwrap()) >> 6;
  let h4 = u32::from_le_bytes(block[12..16].try_into().unwrap()) >> 8 | hibit;

  (h0, h1, h2, h3, h4)
}

/// Calculates the `d` values for Poly1305.
///
/// This function computes the `d` values based on the `h` values and key-related
/// values (`r` and `s` arrays). These calculations are part of the Poly1305 algorithm
/// for message authentication.
///
/// # Arguments
/// * `h0`, `h1`, `h2`, `h3`, `h4` - The `h` values from the Poly1305 state.
/// * `r0`, `r1`, `r2`, `r3`, `r4` - The `r` values from the Poly1305 key.
/// * `s1`, `s2`, `s3`, `s4` - The `s` values, which are derived from the `r` values.
///
/// # Returns
/// A tuple of five `u64` values representing the calculated `d` values.
pub fn calculate_poly1305_d_values(
  h0: u32,
  h1: u32,
  h2: u32,
  h3: u32,
  h4: u32,
  r0: u32,
  r1: u32,
  r2: u32,
  r3: u32,
  r4: u32,
  s1: u32,
  s2: u32,
  s3: u32,
  s4: u32,
) -> (u64, u64, u64, u64, u64) {
  let d0 = h0 as u64 * r0 as u64
    + h1 as u64 * s4 as u64
    + h2 as u64 * s3 as u64
    + h3 as u64 * s2 as u64
    + h4 as u64 * s1 as u64;

  let d1 = h0 as u64 * r1 as u64
    + h1 as u64 * r0 as u64
    + h2 as u64 * s4 as u64
    + h3 as u64 * s3 as u64
    + h4 as u64 * s2 as u64;

  let d2 = h0 as u64 * r2 as u64
    + h1 as u64 * r1 as u64
    + h2 as u64 * r0 as u64
    + h3 as u64 * s4 as u64
    + h4 as u64 * s3 as u64;

  let d3 = h0 as u64 * r3 as u64
    + h1 as u64 * r2 as u64
    + h2 as u64 * r1 as u64
    + h3 as u64 * r0 as u64
    + h4 as u64 * s4 as u64;

  let d4 = h0 as u64 * r4 as u64
    + h1 as u64 * r3 as u64
    + h2 as u64 * r2 as u64
    + h3 as u64 * r1 as u64
    + h4 as u64 * r0 as u64;

  (d0, d1, d2, d3, d4)
}

/// Applies the modulo p reduction to the Poly1305 hash.
///
/// This function performs the modulo p reduction on the hash state, which is
/// part of the Poly1305 algorithm. It modifies the hash state in-place.
///
/// # Arguments
/// * `hash` - A mutable reference to the Poly1305 hash state.
/// * `d0`, `d1`, `d2`, `d3`, `d4` - Mutable references to the `d` values.
pub fn apply_poly1305_mod_p(
  hash: &mut [u32; 5],
  d0: &mut u64,
  d1: &mut u64,
  d2: &mut u64,
  d3: &mut u64,
  d4: &mut u64,
) {
  let mut c = (*d0 >> 26) as u32;
  hash[0] = (*d0 as u32) & 0x3ff_ffff;
  *d1 += c as u64;

  c = (*d1 >> 26) as u32;
  hash[1] = (*d1 as u32) & 0x3ff_ffff;
  *d2 += c as u64;

  c = (*d2 >> 26) as u32;
  hash[2] = (*d2 as u32) & 0x3ff_ffff;
  *d3 += c as u64;

  c = (*d3 >> 26) as u32;
  hash[3] = (*d3 as u32) & 0x3ff_ffff;
  *d4 += c as u64;

  c = (*d4 >> 26) as u32;
  hash[4] = (*d4 as u32) & 0x3ff_ffff;
  hash[0] += c * 5;

  c = (hash[0] >> 26) as u32;
  hash[0] &= 0x3ff_ffff;
  hash[1] += c;
}

/// Finalizes the Poly1305 hash computation.
///
/// This function finalizes the Poly1305 hash computation by performing the
/// necessary adjustments and reductions on the internal state.
///
/// # Arguments
/// * `hash` - A mutable reference to the Poly1305 hash state.
pub fn finalize_poly1305_hash(hash: &mut [u32; 5]) {
  let mut c = hash[1] >> 26;
  hash[1] &= 0x3ff_ffff;
  hash[2] += c;

  c = hash[2] >> 26;
  hash[2] &= 0x3ff_ffff;
  hash[3] += c;

  c = hash[3] >> 26;
  hash[3] &= 0x3ff_ffff;
  hash[4] += c;

  c = hash[4] >> 26;
  hash[4] &= 0x3ff_ffff;
  hash[0] += c * 5;

  c = hash[0] >> 26;
  hash[0] &= 0x3ff_ffff;
  hash[1] += c;

  let mut g0 = hash[0].wrapping_add(5);
  c = g0 >> 26;
  g0 &= 0x3ff_ffff;

  let mut g1 = hash[1].wrapping_add(c);
  c = g1 >> 26;
  g1 &= 0x3ff_ffff;

  let mut g2 = hash[2].wrapping_add(c);
  c = g2 >> 26;
  g2 &= 0x3ff_ffff;

  let mut g3 = hash[3].wrapping_add(c);
  c = g3 >> 26;
  g3 &= 0x3ff_ffff;

  let mut g4 = hash[4].wrapping_add(c).wrapping_sub(1 << 26);

  let mut mask = (g4 >> 31 - 1).wrapping_sub(1);
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = !mask;
  hash[0] = (hash[0] & mask) | g0;
  hash[1] = (hash[1] & mask) | g1;
  hash[2] = (hash[2] & mask) | g2;
  hash[3] = (hash[3] & mask) | g3;
  hash[4] = (hash[4] & mask) | g4;

  hash[0] |= hash[1] << 26;
  hash[1] = (hash[1] >> 6) | (hash[2] << 20);
  hash[2] = (hash[2] >> 12) | (hash[3] << 14);
  hash[3] = (hash[3] >> 18) | (hash[4] << 8);
}

/// Applies the pad to the Poly1305 hash.
///
/// This function applies the pad (part of the key) to the Poly1305 hash. It is
/// called as part of the finalization process of the Poly1305 algorithm.
///
/// # Arguments
/// * `hash` - A mutable reference to the Poly1305 hash state.
/// * `pad` - The pad values from the Poly1305 key.
pub fn apply_poly1305_pad(hash: &mut [u32; 5], pad: [u32; 4]) {
  let mut f: u64 = hash[0] as u64 + pad[0] as u64;
  hash[0] = f as u32;

  f = hash[1] as u64 + pad[1] as u64 + (f >> 32);
  hash[1] = f as u32;

  f = hash[2] as u64 + pad[2] as u64 + (f >> 32);
  hash[2] = f as u32;

  f = hash[3] as u64 + pad[3] as u64 + (f >> 32);
  hash[3] = f as u32;
}

/// Converts the Poly1305 hash into a tag.
///
/// This function converts the Poly1305 hash state into a 16-byte tag, which is
/// the final output of the Poly1305 algorithm.
///
/// # Arguments
/// * `hash` - A reference to the Poly1305 hash state.
///
/// # Returns
/// A 16-byte array representing the Poly1305 tag.
pub fn poly1305_hash_to_tag(hash: &[u32; 5]) -> [u8; 16] {
  let mut tag = [0u8; 16];
  tag[0..4].copy_from_slice(&hash[0].to_le_bytes());
  tag[4..8].copy_from_slice(&hash[1].to_le_bytes());
  tag[8..12].copy_from_slice(&hash[2].to_le_bytes());
  tag[12..16].copy_from_slice(&hash[3].to_le_bytes());
  tag
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
