use super::Permutation;

pub struct Poly1305 {
  r: [u32; 5],
  h: [u32; 5],
  pad: [u32; 4],
}

impl Poly1305 {
  pub fn new() -> Self {
    Self::default()
  }

  fn compute_block(&mut self, block: [u8; 16], partial: bool) {
    let hibit = if partial { 0 } else { 1 << 24 };

    let r0 = self.r[0];
    let r1 = self.r[1];
    let r2 = self.r[2];
    let r3 = self.r[3];
    let r4 = self.r[4];

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    // h += m
    let h0 =
      self.h[0].wrapping_add(u32::from_le_bytes(block[0..4].try_into().unwrap())) & 0x3ff_ffff;
    let h1 =
      self.h[1].wrapping_add(u32::from_le_bytes(block[3..7].try_into().unwrap()) >> 2) & 0x3ff_ffff;
    let h2 = self.h[2].wrapping_add(u32::from_le_bytes(block[6..10].try_into().unwrap()) >> 4)
      & 0x3ff_ffff;
    let h3 = self.h[3].wrapping_add(u32::from_le_bytes(block[9..13].try_into().unwrap()) >> 6)
      & 0x3ff_ffff;
    let h4 =
      self.h[4].wrapping_add(u32::from_le_bytes(block[12..16].try_into().unwrap()) >> 8) | hibit;

    // h *= r

    let d0 = h0 as u64 * r0 as u64
      + h1 as u64 * s4 as u64
      + h2 as u64 * s3 as u64
      + h3 as u64 * s2 as u64
      + h4 as u64 * s1 as u64;

    let mut d1 = h0 as u64 * r1 as u64
      + h1 as u64 * r0 as u64
      + h2 as u64 * s4 as u64
      + h3 as u64 * s3 as u64
      + h4 as u64 * s2 as u64;

    let mut d2 = h0 as u64 * r2 as u64
      + h1 as u64 * r1 as u64
      + h2 as u64 * r0 as u64
      + h3 as u64 * s4 as u64
      + h4 as u64 * s3 as u64;

    let mut d3 = h0 as u64 * r3 as u64
      + h1 as u64 * r2 as u64
      + h2 as u64 * r1 as u64
      + h3 as u64 * r0 as u64
      + h4 as u64 * s4 as u64;

    let mut d4 = h0 as u64 * r4 as u64
      + h1 as u64 * r3 as u64
      + h2 as u64 * r2 as u64
      + h3 as u64 * r1 as u64
      + h4 as u64 * r0 as u64;

    // (partial) h %= p
    let mut c = (d0 >> 26) as u32;
    self.h[0] = d0 as u32 & 0x3ff_ffff;
    d1 += c as u64;

    c = (d1 >> 26) as u32;
    self.h[1] = d1 as u32 & 0x3ff_ffff;
    d2 += c as u64;

    c = (d2 >> 26) as u32;
    self.h[2] = d2 as u32 & 0x3ff_ffff;
    d3 += c as u64;

    c = (d3 >> 26) as u32;
    self.h[3] = d3 as u32 & 0x3ff_ffff;
    d4 += c as u64;

    c = (d4 >> 26) as u32;
    self.h[4] = d4 as u32 & 0x3ff_ffff;
    self.h[0] += c * 5;

    c = (self.h[0] >> 26) as u32;
    self.h[0] &= 0x3ff_ffff;
    self.h[1] += c;
  }

  fn finalize(&mut self) -> [u8; 16] {
    let mut c = self.h[1] >> 26;
    self.h[1] &= 0x3ff_ffff;
    self.h[2] += c;

    c = self.h[2] >> 26;
    self.h[2] &= 0x3ff_ffff;
    self.h[3] += c;

    c = self.h[3] >> 26;
    self.h[3] &= 0x3ff_ffff;
    self.h[4] += c;

    c = self.h[4] >> 26;
    self.h[4] &= 0x3ff_ffff;
    self.h[0] += c * 5;

    c = self.h[0] >> 26;
    self.h[0] &= 0x3ff_ffff;
    self.h[1] += c;

    let mut g0 = self.h[0].wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x3ff_ffff;

    let mut g1 = self.h[1].wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x3ff_ffff;

    let mut g2 = self.h[2].wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x3ff_ffff;

    let mut g3 = self.h[3].wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x3ff_ffff;

    let mut g4 = self.h[4].wrapping_add(c).wrapping_sub((1 << 26));

    let mut mask = (g4 >> 31 - 1).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = !mask;
    self.h[0] = (self.h[0] & mask) | g0;
    self.h[1] = (self.h[1] & mask) | g1;
    self.h[2] = (self.h[2] & mask) | g2;
    self.h[3] = (self.h[3] & mask) | g3;
    self.h[4] = (self.h[4] & mask) | g4;

    self.h[0] |= self.h[1] << 26;
    self.h[1] = (self.h[1] >> 6) | (self.h[2] << 20);
    self.h[2] = (self.h[2] >> 12) | (self.h[3] << 14);
    self.h[3] = (self.h[3] >> 18) | (self.h[4] << 8);

    let mut f: u64 = self.h[0] as u64 + self.pad[0] as u64;
    self.h[0] = f as u32;

    f = self.h[1] as u64 + self.pad[1] as u64 + (f >> 32);
    self.h[1] = f as u32;

    f = self.h[2] as u64 + self.pad[2] as u64 + (f >> 32);
    self.h[2] = f as u32;

    f = self.h[3] as u64 + self.pad[3] as u64 + (f >> 32);
    self.h[3] = f as u32;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&self.h[0].to_le_bytes());
    tag[4..8].copy_from_slice(&self.h[1].to_le_bytes());
    tag[8..12].copy_from_slice(&self.h[2].to_le_bytes());
    tag[12..16].copy_from_slice(&self.h[3].to_le_bytes());

    tag
  }
}

impl Permutation for Poly1305 {
  fn init(&mut self, key: &[u8], _iv: &[u8]) {
    self.r[0] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x3ff_ffff;
    self.r[1] = u32::from_le_bytes([key[3], key[4], key[5], key[6]]) & 0x3ff_ff03;
    self.r[2] = u32::from_le_bytes([key[6], key[7], key[8], key[9]]) & 0x3ff_c0ff;
    self.r[3] = u32::from_le_bytes([key[9], key[10], key[11], key[12]]) & 0x3f0_3fff;
    self.r[4] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]) & 0x00f_ffff;
    self.pad[0] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
    self.pad[1] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
    self.pad[2] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
    self.pad[3] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
  }

  fn process(&mut self, data: &[u8]) -> Vec<u8> {
    let mut blocks = data.chunks_exact(16);
    let partial = blocks.remainder();

    while let Some(block) = blocks.next() {
      self.compute_block(block.try_into().unwrap(), false);
    }

    if !partial.is_empty() {
      let mut block = [0u8; 16];
      block[..partial.len()].copy_from_slice(partial);
      // this must end with 1 or during conversions trailing zeros will be lost
      block[partial.len()] = 1;
      self.compute_block(block, true);
    }

    self.finalize().to_vec()
  }

  fn clear(&mut self) {
    self.r = [0u32; 5];
    self.h = [0u32; 5];
    self.pad = [0u32; 4];
  }
}

impl Default for Poly1305 {
  fn default() -> Self {
    Self {
      r: [0u32; 5],
      h: [0u32; 5],
      pad: [0u32; 4],
    }
  }
}
