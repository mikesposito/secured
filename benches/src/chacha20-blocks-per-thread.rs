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
  let mut group = c.benchmark_group("ChaCha20 / process_in_place / Blocks Per Thread");
  let plot_config = PlotConfiguration::default().summary_scale(criterion::AxisScale::Logarithmic);
  group.plot_config(plot_config);

  let data_size = 1 * 1024 * MB;
  let blocks_per_thread_options = [10, 1000, 10_000, 100_000, 1_000_000];

  for &blocks_per_thread in &blocks_per_thread_options {
    let key = [0u8; 32];
    let iv = [1u8; CHACHA20_NONCE_SIZE];

    group.throughput(Throughput::Bytes(data_size as u64));

    let mut chacha20 = ChaCha20::default().set_blocks_per_thread(blocks_per_thread);
    chacha20.init(&key, &iv);

    let bench_id = format!("{data_size}_bpt_{blocks_per_thread}");
    group.bench_with_input(
      BenchmarkId::new("process_in_place", bench_id),
      &data_size,
      |b, &data_size| {
        let mut bytes = vec![0u8; data_size];
        b.iter(|| chacha20.process_in_place(&mut bytes));
      },
    );
  }

  group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
