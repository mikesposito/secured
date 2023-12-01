use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secured_cipher::chacha20::{KEY_SIZE, NONCE_SIZE};
use secured_enclave::Enclave;

const KB: usize = 1024;

fn bench(c: &mut Criterion) {
  let mut group = c.benchmark_group("enclave");

  for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
    let key = [0u8; KEY_SIZE];

    group.throughput(Throughput::Bytes(*size as u64));
    group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, &_size| {
      b.iter(|| {
        let buf = vec![0u8; *size];
        Enclave::<&str, NONCE_SIZE>::from_plain_bytes("Metadata", key, buf)
      });
    });
  }

  group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
