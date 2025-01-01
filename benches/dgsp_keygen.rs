use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dgsp::dgsp::DGSP;

fn csr_benchmarks(c: &mut Criterion) {
    let alg_name = "keygen";
    let mut group = c.benchmark_group(format!("DGSP_{}", alg_name));

    {
        group.bench_function(BenchmarkId::new(alg_name, ""), |b| {
            b.iter(|| {
                black_box(DGSP::keygen_user());
            });
        });
    }

    group.finish();
}

criterion_group!(benches, csr_benchmarks);
criterion_main!(benches);
