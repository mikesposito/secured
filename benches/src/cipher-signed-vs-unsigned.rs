use criterion::{
  black_box, criterion_group, criterion_main, BenchmarkId, Criterion, PlotConfiguration, Throughput,
};
use secured_cipher::{
  algorithm::{chacha20::CHACHA20_NONCE_SIZE, Blake3Mac},
  ChaCha20, Cipher, CipherMode, Poly1305,
};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

fn bench(c: &mut Criterion) {
  let mut group = c.benchmark_group("Cipher / Signed vs Unsigned");
  let plot_config = PlotConfiguration::default().summary_scale(criterion::AxisScale::Logarithmic);
  group.plot_config(plot_config);

  let data_size = 1024 * MB;
  let blocks_per_thread_options = [1000];

  for &blocks_per_thread in &blocks_per_thread_options {
    let key = [0u8; 32];
    let iv = [1u8; CHACHA20_NONCE_SIZE];
    let bench_id = format!("1GB_{blocks_per_thread}_blocks_per_thread");

    group.throughput(Throughput::Bytes(data_size as u64));

    // Signed cipher using ChaCha20 with Poly1305 for authentication
    let mut poly1305_cipher = Cipher::new(CipherMode::Custom(
      Box::new(ChaCha20::default().set_blocks_per_thread(blocks_per_thread)),
      Some(Box::new(Poly1305::new())),
    ));
    poly1305_cipher.init(&key, &iv);
    group.bench_with_input(
      BenchmarkId::new("ChaCha20 + Poly1305 signed", &bench_id),
      &data_size,
      |b, &data_size| {
        b.iter(|| {
          let mut bytes = vec![0u8; data_size];
          poly1305_cipher.encrypt_in_place(&mut bytes);
          poly1305_cipher.sign(vec![], bytes)
        });
      },
    );

    // Signed cipher using ChaCha20 with Blake3 for authentication
    let mut blake3_cipher = Cipher::new(CipherMode::Custom(
      Box::new(ChaCha20::default().set_blocks_per_thread(blocks_per_thread)),
      Some(Box::new(Blake3Mac::default())),
    ));
    blake3_cipher.init(&key, &iv);
    group.bench_with_input(
      BenchmarkId::new("ChaCha20 + Blake3 signed", &bench_id),
      &data_size,
      |b, &data_size| {
        b.iter(|| {
          let mut bytes = vec![0u8; data_size];
          blake3_cipher.encrypt_in_place(&mut bytes);
          blake3_cipher.sign(vec![], bytes)
        });
      },
    );

    // Unsigned cipher using ChaCha20 without any AEAD algorithm
    let mut unsigned_cipher = Cipher::new(CipherMode::Custom(
      Box::new(ChaCha20::default().set_blocks_per_thread(blocks_per_thread)),
      None,
    ));
    unsigned_cipher.init(&key, &iv);
    group.bench_with_input(
      BenchmarkId::new("Unsigned", &bench_id),
      &data_size,
      |b, &data_size| {
        let mut bytes = vec![0u8; data_size];
        b.iter(|| unsigned_cipher.encrypt_in_place(black_box(&mut bytes)));
      },
    );
  }

  group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
