use std::{cmp, io::Write};

use crate::Cipher;

use super::core::CHACHA20_BLOCK_SIZE;

const CHUNK_SIZE: usize = CHACHA20_BLOCK_SIZE * 4096;

/// `ChaCha20Writer` is a wrapper around a `Write` implementation that encrypts data using the
/// a stream cipher.
pub struct ChaCha20Writer<W> {
  inner: W,
  cipher: Cipher,
  buffer: Vec<u8>,
}

impl<W: Write> ChaCha20Writer<W> {
  pub fn new(inner: W, cipher: Cipher) -> Self {
    Self {
      inner,
      cipher,
      buffer: Vec::new(),
    }
  }

  pub fn flush_buffer(&mut self) -> std::io::Result<()> {
    if self.buffer.is_empty() {
      return Ok(());
    }

    let mut bytes = self
      .buffer
      .drain(..cmp::min(self.buffer.len(), CHUNK_SIZE))
      .collect::<Vec<u8>>();
    self.cipher.encrypt_in_place(&mut bytes);

    self.inner.write_all(&bytes)?;
    self.buffer.clear();
    Ok(())
  }

  pub fn finalize(mut self) -> std::io::Result<()> {
    self.flush_buffer()?;
    self.inner.flush()
  }
}

impl<W: Write> Write for ChaCha20Writer<W> {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    self.buffer.extend_from_slice(buf);

    if self.buffer.len() >= CHUNK_SIZE {
      self.flush_buffer()?;
    }

    Ok(buf.len())
  }

  fn flush(&mut self) -> std::io::Result<()> {
    self.flush_buffer()
  }
}
