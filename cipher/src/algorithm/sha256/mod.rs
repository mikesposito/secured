pub mod core;

use super::buffer::Buffer;
use core::{block_bytes_to_words, compress_block, Sha256Hash, INITIAL_HASH};
use std::io::{Read, Write};

// 10 * 64 = 640 bytes (10 blocks of 64 bytes each)
const SHA256_BUFFER_SIZE: usize = 64 * 10;

pub struct Sha256 {
  hash: Sha256Hash,
  buffer: Buffer<SHA256_BUFFER_SIZE>,
  finalized: bool,
}

impl Default for Sha256 {
  fn default() -> Self {
    println!("Hash update: {:?}", INITIAL_HASH);
    Self {
      hash: INITIAL_HASH,
      buffer: Buffer::new(),
      finalized: false,
    }
  }
}

impl Sha256 {
  /// Resets the hash to its initial state.
  pub fn reset(&mut self) {
    self.hash = INITIAL_HASH;
    self.buffer.clear(true);
    self.finalized = false;
  }

  fn process_buffer(&mut self, finalize_remainder: bool) -> std::io::Result<()> {
    // If the hasher is finalized, we cannot process any more data.
    if self.finalized {
      return Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Cannot write to a finalized hasher",
      ));
    }

    if self.buffer.is_empty() {
      return Ok(());
    }

    // Divide the buffer into 64-byte blocks and process each block,
    // ignoring any remaining bytes that do not fill a complete block.
    while self.buffer.len() >= 64 {
      // Read 64 bytes
      let mut block = [0u8; 64];
      self.buffer.read_exact(&mut block)?;
      // Process
      self.process_block(&block_bytes_to_words(&block));
    }

    // If we are finalizing, pad the remaining bytes and process the last block.
    if finalize_remainder {
      let remainder = self.buffer.len();
      let bit_length = (self.buffer.total_bytes_written() as u64) * 8;
      let bit_length_bytes = bit_length.to_be_bytes();
      let mut block = [0u8; 64];
      self.buffer.read_exact(&mut block[..remainder])?;

      // Pad the current block adding a 1 bit (0x80) at the end of the data
      // and leaving the rest as zeroes.
      block[remainder] = 0x80;

      if remainder >= 56 {
        // If the remainder is 56 bytes or more, we need to process the current block
        // and then prepare a second block with the length at the end.
        self.process_block(&block_bytes_to_words(&block));

        // Prepare and process second empty block, with the length at the end
        let mut final_block = [0u8; 64];
        final_block[56..64].copy_from_slice(&bit_length_bytes);
        self.process_block(&block_bytes_to_words(&final_block));
      } else {
        // If the remainder is less than 56 bytes, we can pad the current block
        // and write the length at the end.
        println!("The total bytes written: {:?}", bit_length_bytes);
        block[56..64].copy_from_slice(&bit_length_bytes);
        self.process_block(&block_bytes_to_words(&block));
      }

      self.finalized = true;
    }

    Ok(())
  }

  pub fn finalize(&mut self) -> std::io::Result<[u8; 32]> {
    self.process_buffer(true)?;

    let mut result = [0u8; 32];
    for (i, &word) in self.hash.iter().enumerate() {
      result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(result)
  }

  fn process_block(&mut self, block: &[u32; 16]) {
    compress_block(block, &mut self.hash);
    println!("Hash update: {:?}", self.hash);
  }
}

impl Write for Sha256 {
  fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
    let mut bytes_written = 0;

    // Write data to the buffer.
    for chunk in data.chunks(SHA256_BUFFER_SIZE) {
      bytes_written += self.buffer.write(chunk)?;
      // If the buffer is full, flush it.
      if self.buffer.len() >= SHA256_BUFFER_SIZE {
        self.process_buffer(false)?;
      }
    }

    Ok(bytes_written)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::io::Write;

  #[test]
  fn it_should_process_sha256() {
    let mut hasher = Sha256::default();
    let data = b"abc";

    hasher.write(data).unwrap();

    assert_eq!(
      hasher.finalize().unwrap(),
      [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad
      ]
    );
  }
}
