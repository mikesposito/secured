pub const STATE_WORDS: usize = 32;

pub const HASH_WORDS: usize = 8;

pub const SCHEDULE_WORDS: usize = 64;

pub const INITIAL_HASH: Sha256Hash = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const K: [u32; 64] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub type Sha256Hash = [u32; HASH_WORDS];

pub type MessageSchedule = [u32; SCHEDULE_WORDS];

pub type WorkingVariables = [u32; 8];

pub fn compress_block(block: &[u32; 16], hash: &mut Sha256Hash) {
  let mut v = init_working_variables(hash);
  compress_schedule(&schedule_from_block(block), &mut v);
  update_hash(hash, &v);
}

pub fn block_bytes_to_words(block: &[u8; 64]) -> [u32; 16] {
  let mut words = [0u32; 16];
  for (i, word) in block.chunks(4).enumerate() {
    words[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
  }
  words
}

fn init_working_variables(hash: &Sha256Hash) -> WorkingVariables {
  [
    hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
  ]
}

fn schedule_from_block(block: &[u32; 16]) -> MessageSchedule {
  let mut schedule = [0u32; SCHEDULE_WORDS];

  // The first 16 words of the message schedule are the block itself.
  for i in 0..16 {
    schedule[i] = block[i];
  }
  // The remaining words are generated using the sigma functions.
  for i in 16..SCHEDULE_WORDS {
    schedule[i] = schedule[i - 16]
      .wrapping_add(sig0(schedule[i - 15]))
      .wrapping_add(schedule[i - 7])
      .wrapping_add(sig1(schedule[i - 2]));
  }

  schedule
}

fn compress_schedule(schedule: &MessageSchedule, v: &mut WorkingVariables) {
  for i in 0..SCHEDULE_WORDS {
    let t1 = v[7]
      .wrapping_add(big_sig1(v[4]))
      .wrapping_add(ch(v[4], v[5], v[6]))
      .wrapping_add(schedule[i])
      .wrapping_add(K[i]);

    let t2 = big_sig0(v[0]).wrapping_add(maj(v[0], v[1], v[2]));

    v[7] = v[6];
    v[6] = v[5];
    v[5] = v[4];
    v[4] = v[3].wrapping_add(t1);
    v[3] = v[2];
    v[2] = v[1];
    v[1] = v[0];
    v[0] = t1.wrapping_add(t2);
  }
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
  (x & y) ^ (x & z) ^ (y & z)
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
  (x & y) ^ ((!x) & z)
}

fn update_hash(hash: &mut Sha256Hash, v: &WorkingVariables) {
  for (h, w) in hash.iter_mut().zip(v.iter()) {
    *h = h.wrapping_add(*w);
  }
}

fn rotr(x: u32, n: u32) -> u32 {
  (x >> n) | (x << (32 - n))
}

fn sig0(x: u32) -> u32 {
  rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn sig1(x: u32) -> u32 {
  rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

fn big_sig0(x: u32) -> u32 {
  rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn big_sig1(x: u32) -> u32 {
  rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}
