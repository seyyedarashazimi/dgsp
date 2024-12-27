use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dgsp::dgsp::DGSP;
use dgsp::sphincs_plus::SPX_N;
use rand::seq::SliceRandom;
use rand::thread_rng;

const GROUP_SIZE: usize = 1 << 10;

struct CsrData {
    seed_u: [u8; SPX_N],
}

struct Setup {
    csr_inputs: Vec<CsrData>,
}

fn setup_csr() -> Setup {
    let mut csr_inputs = Vec::new();

    for _ in 0..GROUP_SIZE {
        let seed_u = DGSP::keygen_user();
        csr_inputs.push(CsrData { seed_u });
    }

    Setup { csr_inputs }
}

fn csr_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP csr only");

    {
        let setup_data = setup_csr();

        let Setup { csr_inputs } = setup_data;

        group.bench_function(
            BenchmarkId::new("csr", format!("(GROUP_SIZE={})", GROUP_SIZE)),
            |b| {
                b.iter(|| {
                    let data = csr_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(DGSP::cert_sign_req_user(&data.seed_u, 1));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, csr_benchmarks);
criterion_main!(benches);
