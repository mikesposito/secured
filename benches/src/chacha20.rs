use criterion::{
  criterion_group, criterion_main, BenchmarkId, Criterion, PlotConfiguration, Throughput,
};
use secured_cipher::{
  algorithm::chacha20::CHACHA20_NONCE_SIZE, AlgorithmKeyIVInit, AlgorithmProcess,
  AlgorithmProcessInPlace, ChaCha20,
};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

fn bench(c: &mut Criterion) {
  let mut group = c.benchmark_group("ChaCha20");
  let plot_config = PlotConfiguration::default().summary_scale(criterion::AxisScale::Logarithmic);
  group.plot_config(plot_config);

  for size in &[
    KB,
    2 * KB,
    4 * KB,
    8 * KB,
    MB,
    2 * MB,
    4 * MB,
    8 * MB,
    100 * MB,
    200 * MB,
    400 * MB,
    800 * MB,
  ] {
    let key = [0u8; 32];
    let iv = [1u8; CHACHA20_NONCE_SIZE];

    group.throughput(Throughput::Bytes(*size as u64));

    let mut chacha20 = ChaCha20::new();
    chacha20.init(&key, &iv);

    group.bench_with_input(BenchmarkId::new("process", size), size, |b, &_size| {
      let mut bytes = vec![0u8; *size];
      b.iter(|| chacha20.process_in_place(&mut bytes));
    });

    group.bench_with_input(
      BenchmarkId::new("process_in_place", size),
      size,
      |b, &_size| {
        let mut bytes = vec![0u8; *size];
        b.iter(|| chacha20.process(&mut bytes));
      },
    );
  }

  group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
