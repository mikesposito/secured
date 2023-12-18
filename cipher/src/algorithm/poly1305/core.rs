//! Poly1305 Authentication Algorithm Implementation
//!
//! This module provides an implementation of the Poly1305 algorithm,
//! as specified in RFC 7539 by the Internet Engineering Task Force (IETF).
//!
//! The constants and logic, as well as the test vectors used in this module,
//! are based on and verifiable against the specifications detailed in the IETF paper:
//! "ChaCha20 and Poly1305 for IETF Protocols" (RFC 7539).
//! This can be accessed at https://datatracker.ietf.org/doc/html/rfc7539.
//!
//! The module is designed to be compliant with the RFC 7539 standard, ensuring reliability
//! and correctness of the cryptographic operations as per the established IETF guidelines.

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

  c = hash[0] >> 26;
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

  let mut mask = (g4 >> (31 - 1)).wrapping_sub(1);
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
