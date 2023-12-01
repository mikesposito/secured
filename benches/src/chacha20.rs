use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secured_cipher::chacha20::{ChaChaStream, KEY_SIZE, NONCE_SIZE};

const KB: usize = 1024;

fn bench(c: &mut Criterion) {
  let mut group = c.benchmark_group("ChaChaStream");

  for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
    let key = [0u8; KEY_SIZE];
    let iv = [1u8; NONCE_SIZE];

    group.throughput(Throughput::Bytes(*size as u64));

    group.bench_with_input(BenchmarkId::new("new", size), size, |b, &_size| {
      b.iter(|| ChaChaStream::new(key, iv));
    });

    let mut stream = ChaChaStream::new(key, iv);
    group.bench_with_input(BenchmarkId::new("process", size), size, |b, &_size| {
      b.iter(|| stream.process(&vec![0u8; *size]));
    });
  }

  group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
