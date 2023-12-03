use super::{
  core::{
    apply_poly1305_mod_p, apply_poly1305_pad, calculate_poly1305_d_values,
    calculate_poly1305_h_values, finalize_poly1305_hash, poly1305_hash_to_tag,
  },
  Permutation,
};

/// Define the Poly1305 struct for the Poly1305 MAC algorithm.
pub struct Poly1305 {
  // r: 5-element array storing part of the key.
  r: [u32; 5],
  // h: 5-element array, the internal state for the hash calculation.
  h: [u32; 5],
  // pad: 4-element array storing the other part of the key.
  pad: [u32; 4],
}

impl Poly1305 {
  /// Creates a new instance of Poly1305.
  ///
  /// This constructor initializes a new Poly1305 instance with default values.
  /// It is typically used to start a new message authentication code (MAC) computation.
  ///
  /// # Returns
  /// A new instance of `Poly1305`.
  pub fn new() -> Self {
    Self::default()
  }

  /// Computes a block of data for the MAC.
  ///
  /// This method processes a 16-byte block of data and updates the internal state
  /// (`h`) based on the block data and the Poly1305 algorithm. It handles both full
  /// and partial blocks, where a partial block is less than 16 bytes.
  ///
  /// # Arguments
  /// * `block` - A 16-byte array representing the data block to be processed.
  /// * `partial` - A boolean indicating whether the block is a partial block.
  ///
  /// # Notes
  /// Partial blocks are handled differently in the algorithm, as indicated by the `partial` flag.
  fn compute_block(&mut self, block: [u8; 16], partial: bool) {
    let hibit = if partial { 0 } else { 1 << 24 };

    let (r0, r1, r2, r3, r4) = (self.r[0], self.r[1], self.r[2], self.r[3], self.r[4]);
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);

    // h += m
    let (h0, h1, h2, h3, h4) = calculate_poly1305_h_values(&block, hibit);

    // h *= r
    let (mut d0, mut d1, mut d2, mut d3, mut d4) =
      calculate_poly1305_d_values(h0, h1, h2, h3, h4, r0, r1, r2, r3, r4, s1, s2, s3, s4);

    // (partial) h %= p
    apply_poly1305_mod_p(&mut self.h, &mut d0, &mut d1, &mut d2, &mut d3, &mut d4)
  }

  /// Finalizes the MAC computation and returns the resulting tag.
  ///
  /// This method completes the Poly1305 MAC computation by finalizing the hash calculation,
  /// applying the pad, and then converting the final hash state into a 16-byte tag.
  ///
  /// It should be called after all blocks of data have been processed using `compute_block`.
  ///
  /// # Returns
  /// A 16-byte array representing the final MAC tag.
  fn finalize(&mut self) -> [u8; 16] {
    // Finalize the hash calculation
    finalize_poly1305_hash(&mut self.h);

    // Apply the padding to the hash
    apply_poly1305_pad(&mut self.h, self.pad);

    // Convert the hash to a tag
    poly1305_hash_to_tag(&self.h)
  }
}

impl Permutation for Poly1305 {
  /// Initializes the Poly1305 state with the given key.
  ///
  /// This method sets up the Poly1305 state using a 32-byte key. The key is split
  /// into two parts: the `r` array (for the algorithm's internal state) and the `pad`
  /// (used in the final computation steps).
  ///
  /// # Arguments
  /// * `key` - A byte slice containing the 32-byte key.
  /// * `_iv` - An optional Initialization Vector, not used in Poly1305.
  ///
  /// # Returns
  /// A mutable reference to the initialized Poly1305 instance.
  ///
  /// # Notes
  /// The Initialization Vector (`_iv`) is not used in Poly1305 and can be passed as an empty slice.
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

  /// Processes the given data and computes the MAC.
  ///
  /// This method processes the input data in 16-byte blocks to compute the
  /// message authentication code (MAC). If the data does not divide evenly into
  /// 16-byte blocks, the final block is padded as necessary.
  ///
  /// # Arguments
  /// * `data` - A byte slice representing the data to be processed.
  ///
  /// # Returns
  /// A vector of bytes (`Vec<u8>`) containing the computed MAC.
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

  /// Clears the internal state of the Poly1305 instance.
  ///
  /// This method resets the internal state variables (`r`, `h`, and `pad`) to zero.
  /// It is useful for security purposes when the MAC computation is complete and
  /// the instance needs to be cleared before being reused or discarded.
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

/// SignedEnvelope struct for handling data with its associated MAC.
pub struct SignedEnvelope {
  pub header: Vec<u8>,
  pub data: Vec<u8>,
  pub mac: Vec<u8>,
}

impl SignedEnvelope {
  /// Constructs a SignedEnvelope from a vector of bytes.
  ///
  /// # Arguments
  ///  - `bytes`: Vec<u8> where the last 16 bytes are considered the MAC.
  ///  - `mac`: Vec<u8> representing the MAC.
  ///
  /// # Returns
  /// Returns a new SignedEnvelope instance.
  pub fn new(header: Vec<u8>, data: Vec<u8>, mac: Vec<u8>) -> Self {
    Self { header, data, mac }
  }
}

impl From<Vec<u8>> for SignedEnvelope {
  fn from(bytes: Vec<u8>) -> Self {
    let mut offset = 0;

    // Deserialize header
    let header_len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    let header = bytes[offset..offset + header_len].to_vec();

    // Deserialize data
    offset += header_len;
    let data_len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    let data = bytes[offset..offset + data_len].to_vec();

    // Deserialize MAC
    offset += data_len;
    let mac = bytes[offset..offset + 16].to_vec();

    // If the MAC length is not 16, return an error
    if mac.len() != 16 {
      panic!("Unexpected bytes length");
    }

    Self::new(header, data, mac)
  }
}

impl From<SignedEnvelope> for Vec<u8> {
  fn from(envelope: SignedEnvelope) -> Self {
    let mut bytes = Vec::new();

    // Serialize the header length and data
    // Network Byte Order is used
    bytes.extend(&(envelope.header.len() as u32).to_be_bytes());
    bytes.extend(&envelope.header);

    // Serialize the data length and data
    // Network Byte Order is used
    bytes.extend(&(envelope.data.len() as u32).to_be_bytes());
    bytes.extend(&envelope.data);

    // Serialize the MAC
    bytes.extend(&envelope.mac);

    bytes
  }
}
