use criterion::{
  criterion_group, criterion_main, BenchmarkId, Criterion, PlotConfiguration, Throughput,
};
use secured_cipher::chacha20::{ChaChaStream, KEY_SIZE, NONCE_SIZE};

const KB: usize = 1024;
const MB: usize = 1024 * KB;
const GB: usize = 1024 * MB;

fn bench(c: &mut Criterion) {
  let mut group = c.benchmark_group("ChaChaStream");
  let plot_config = PlotConfiguration::default().summary_scale(criterion::AxisScale::Logarithmic);
  group.plot_config(plot_config);

  for size in &[
    KB,
    2 * KB,
    4 * KB,
    8 * KB,
    16 * KB,
    32 * KB,
    64 * KB,
    128 * KB,
    256 * KB,
    512 * KB,
    MB,
    2 * MB,
    4 * MB,
    8 * MB,
    16 * MB,
    32 * MB,
    64 * MB,
    128 * MB,
    256 * MB,
    512 * MB,
    GB,
  ] {
    let key = [0u8; KEY_SIZE];
    let iv = [1u8; NONCE_SIZE];

    group.throughput(Throughput::Bytes(*size as u64));

    // group.bench_with_input(BenchmarkId::new("new", size), size, |b, &_size| {
    //   b.iter(|| ChaChaStream::new(key, iv));
    // });

    let mut stream = ChaChaStream::new(key, iv);
    group.bench_with_input(BenchmarkId::new("process", size), size, |b, &_size| {
      b.iter(|| stream.process(&vec![0u8; *size]));
    });
  }

  group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
