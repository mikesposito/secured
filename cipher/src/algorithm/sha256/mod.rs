pub mod core;

use super::buffer::Buffer;
use core::{block_bytes_to_words, compress_block, pad, Sha256Hash, INITIAL_HASH};
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

  fn flush_buffer(&mut self, finalize_remainder: bool) -> std::io::Result<()> {
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
    // Divide the buffer into 64-byte chunks and process each chunk,
    // ignoring any remaining bytes that do not fill a complete chunk.
    while self.buffer.len() >= 64 {
      // Read 64 bytes
      let mut chunk = [0u8; 64];
      self.buffer.read_exact(&mut chunk)?;
      // Process
      self.process_block(&block_bytes_to_words(&chunk));
    }

    // If we are finalizing, pad the remaining bytes and process the last block.
    // If not, just clear the buffer.
    if finalize_remainder {
      let remainder = self.buffer.len();
      let mut padded_chunk = [0u8; 64];
      self.buffer.read_exact(&mut padded_chunk)?;
      pad(&mut padded_chunk, remainder);
      // Process the last block
      self.process_block(&block_bytes_to_words(&padded_chunk));
      self.finalized = true;
    }

    Ok(())
  }

  fn finalize(&mut self) -> std::io::Result<Vec<u8>> {
    self.flush_buffer(true)?;

    let mut result = Vec::with_capacity(32);
    for &word in &self.hash {
      result.extend_from_slice(&word.to_be_bytes());
    }

    Ok(result)
  }

  fn process_block(&mut self, block: &[u32; 16]) {
    compress_block(block, &mut self.hash);
  }
}

impl Write for Sha256 {
  fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
    let mut bytes_written = 0;

    // Write data to the buffer.
    for chunk in data.chunks(SHA256_BUFFER_SIZE) {
      let len = chunk.len();
      self.buffer.write(chunk)?;
      bytes_written += len;

      // If the buffer is full, flush it.
      if self.buffer.len() >= SHA256_BUFFER_SIZE {
        self.flush_buffer(false)?;
      }
    }

    Ok(bytes_written)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    // Finalize the hash and return the result.
    self.finalize()?;
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
