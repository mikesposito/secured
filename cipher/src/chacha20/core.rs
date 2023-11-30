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
pub const ROUNDS: usize = 20;

/// Performs the quarter round operation on the state.
///
/// This operation modifies four words in the state as per the ChaCha20 algorithm's quarter round rules.
/// It involves a series of addition, XOR, and rotation operations to mix the input words.
///
/// # Arguments
/// * `a`, `b`, `c`, `d` - Indices of the state words to be modified.
/// * `state` - A mutable reference to the 512-bit state array.
pub fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; STATE_WORDS]) {
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

/// Performs the ChaCha20 rounds on the provided state.
///
/// Applies the quarter round operation multiple times as defined by the ROUNDS constant.
/// Optionally, if an additional state is provided, it adds this state to the output after the rounds.
///
/// # Arguments
/// * `out` - A mutable reference to the state array on which the rounds are performed.
/// * `add` - An optional additional state array to add to `out` after the rounds are completed.
pub fn chacha20_rounds(out: &mut [u32; 16], add: Option<[u32; 16]>) {
  for _ in 0..ROUNDS {
    // Odd rounds
    quarter_round(0, 4, 8, 12, out);
    quarter_round(1, 5, 9, 13, out);
    quarter_round(2, 6, 10, 14, out);
    quarter_round(3, 7, 11, 15, out);
    // Even rounds
    quarter_round(0, 5, 10, 15, out);
    quarter_round(1, 6, 11, 12, out);
    quarter_round(2, 7, 8, 13, out);
    quarter_round(3, 4, 9, 14, out);
  }

  if let Some(add) = add {
    // The original ChaCha20 algorithm adds the original state to the output of the rounds.
    for i in 0..16 {
      out[i] = out[i].wrapping_add(add[i]);
    }
  }
}

/// Safely increments the 2-word block counter of the ChaCha20 state.
///
/// This function increments the lower 32 bits of the counter and, if there is an overflow,
/// increments the upper 32 bits. It checks for overflow in the upper bits and panics if detected.
///
/// # Arguments
/// * `counter` - A mutable slice of the two 32-bit words forming the block counter.
pub fn safe_2words_counter_increment(counter: &mut [u32]) {
  let (lower_word_increment, lower_overflow) = counter[0].overflowing_add(1);
  counter[0] = lower_word_increment;
  if lower_overflow {
    let (higher_word_increment, higher_overflow) = counter[1].overflowing_add(1);
    assert!(!higher_overflow, "ChaCha20 block counter overflow");
    counter[1] = higher_word_increment;
  }
}

/// Converts a slice of bytes to a vector of 32-bit unsigned integers.
///
/// The byte slice is divided into chunks of 4 bytes each, with each chunk being converted
/// to a 32-bit integer. This is commonly used to convert input data into the format needed for ChaCha20 processing.
///
/// # Arguments
/// * `bytes` - A slice of bytes to be converted.
///
/// # Returns
/// A vector of 32-bit unsigned integers.
pub fn to_u32_slice(bytes: &[u8]) -> Vec<u32> {
  bytes
    .chunks(4)
    .map(|chunk| {
      let mut array = [0u8; 4];
      for (dest_elem, src_elem) in array.iter_mut().zip(chunk.iter()) {
        *dest_elem = *src_elem;
      }
      u32::from_le_bytes(array)
    })
    .collect()
}

/// Splits a slice of 32-bit words into chunks of 16 words each.
///
/// This function is typically used to prepare data for processing in the ChaCha20 algorithm,
/// where the state operates on 16-word (512-bit) blocks.
///
/// # Arguments
/// * `bytes` - A slice of 32-bit words to be chunked.
///
/// # Returns
/// A vector of 16-word arrays.
pub fn u32_slice_to_16words_chunks(bytes: &[u32]) -> Vec<[u32; 16]> {
  bytes
    .chunks(16)
    .map(|chunk| {
      let mut out = [0u32; 16];
      for (dest_elem, src_elem) in out.iter_mut().zip(chunk.iter()) {
        *dest_elem = *src_elem;
      }
      out
    })
    .collect()
}
