use std::io::{Cursor, Read, Write};

pub struct Buffer<const SIZE: usize> {
  len: usize,
  data: Cursor<[u8; SIZE]>,
}

impl<const SIZE: usize> Buffer<SIZE> {
  pub fn new() -> Self {
    Self {
      len: 0,
      data: Cursor::new([0; SIZE]),
    }
  }

  pub fn is_empty(&self) -> bool {
    self.len == 0
  }

  pub fn len(&self) -> usize {
    self.len
  }

  pub fn clear(&mut self, zeroize: bool) {
    if zeroize {
      self.data.get_mut().fill(0);
    }
    self.len = 0;
  }
}

impl<const SIZE: usize> Write for Buffer<SIZE> {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    if bytes.len() + self.len > SIZE {
      return Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Buffer overflow",
      ));
    }
    let start = self.len;
    let end = start + bytes.len();
    self.data.get_mut()[start..end].copy_from_slice(bytes);
    self.len += bytes.len();
    Ok(self.len)
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
