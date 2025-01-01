use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dgsp::dgsp::DGSP;
use std::time::{Duration, Instant};

fn csr_benchmarks(c: &mut Criterion) {
    let alg_name = "csr";
    let mut group = c.benchmark_group(format!("DGSP_{}", alg_name));

    {
        group.bench_function(BenchmarkId::new(alg_name, ""), |b| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;
                for _ in 0..num_iters {
                    // Precomputation
                    let seed_u = DGSP::keygen_user();

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    black_box(DGSP::cert_sign_req_user(&seed_u, 1));

                    // Stop timer
                    total += start.elapsed();
                }
                total
            });
        });
    }

    group.finish();
}

criterion_group!(benches, csr_benchmarks);
criterion_main!(benches);
