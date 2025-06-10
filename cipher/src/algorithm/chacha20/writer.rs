use std::{cmp, io::Write};

use super::core::CHACHA20_BLOCK_SIZE;
use crate::Cipher;

const CHUNK_SIZE: usize = CHACHA20_BLOCK_SIZE * 4096;

/// `ChaCha20Writer` is a wrapper around a `Write` implementation that encrypts data using the
/// a stream cipher.
pub struct ChaCha20Writer<W> {
  inner: W,
  cipher: Cipher,
  buffer: [u8; CHUNK_SIZE],
  len: usize,
}

impl<W: Write> ChaCha20Writer<W> {
  pub fn new(inner: W, cipher: Cipher) -> Self {
    Self {
      inner,
      cipher,
      buffer: [0; CHUNK_SIZE],
      len: 0,
    }
  }

  pub fn flush_buffer(&mut self) -> std::io::Result<()> {
    if self.len == 0 {
      return Ok(());
    }

    let bytes = &mut self.buffer[..self.len];
    self.cipher.encrypt_in_place(bytes);

    self.inner.write_all(&bytes)?;
    self.clear();
    Ok(())
  }

  pub fn clear(&mut self) {
    self.len = 0;
  }

  pub fn finalize(mut self, zeroize: bool) -> std::io::Result<()> {
    if zeroize {
      self.buffer.fill(0);
    }
    self.flush_buffer()?;
    self.inner.flush()
  }
}

impl<W: Write> Write for ChaCha20Writer<W> {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    let bytes_to_write = cmp::min(buf.len(), CHUNK_SIZE - self.len);
    if bytes_to_write == 0 {
      return Ok(0);
    }
    let start = self.len;
    let end = start + bytes_to_write;
    self.buffer[start..end].copy_from_slice(&buf[..bytes_to_write]);
    self.len += bytes_to_write;

    if self.len == CHUNK_SIZE {
      self.flush_buffer()?;
    }

    Ok(bytes_to_write)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    self.flush_buffer()
  }
}
