use std::io::{Cursor, Read, Write};

pub struct Buffer<const SIZE: usize> {
  data: Cursor<[u8; SIZE]>,
  len: usize,
  total_bytes_written: usize,
}

impl<const SIZE: usize> Buffer<SIZE> {
  pub fn new() -> Self {
    Self {
      data: Cursor::new([0; SIZE]),
      len: 0,
      total_bytes_written: 0,
    }
  }

  pub fn is_empty(&self) -> bool {
    self.len == 0
  }

  pub fn len(&self) -> usize {
    self.len
  }

  pub fn total_bytes_written(&self) -> usize {
    self.total_bytes_written
  }

  pub fn clear(&mut self, zeroize: bool) {
    if zeroize {
      self.data.get_mut().fill(0);
    }
    self.len = 0;
    self.total_bytes_written = 0;
  }
}

impl<const SIZE: usize> Write for Buffer<SIZE> {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    let bytes_to_write = bytes.len().min(SIZE - self.len);
    let slice_range = self.len..(self.len + bytes_to_write);

    self.data.get_mut()[slice_range].copy_from_slice(bytes);
    self.len += bytes_to_write;
    self.total_bytes_written += bytes_to_write;

    Ok(bytes_to_write)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

impl<const SIZE: usize> Read for Buffer<SIZE> {
  fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    let bytes_read = self.data.read(buf)?;
    self.len -= bytes_read.min(self.len);
    Ok(bytes_read)
  }
}
