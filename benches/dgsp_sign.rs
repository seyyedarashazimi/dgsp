use criterion::async_executor::AsyncExecutor;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId,
    Criterion,
};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSPWotsRand, DGSP};
use dgsp::params::DGSP_POS_BYTES;
use dgsp::sphincs_plus::{SphincsPlusSignature, SPX_N};
#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;
use dgsp::PLMInterface;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tempfile::Builder;

#[cfg(feature = "in-memory")]
struct InMemorySetup {
    skm: DGSPManagerSecretKey,
    plm: InMemoryPLM,
}
#[cfg(feature = "in-disk")]
struct InDiskSetup {
    skm: DGSPManagerSecretKey,
    plm: InDiskPLM,
}

#[cfg(feature = "in-memory")]
async fn setup_in_memory_sign() -> InMemorySetup {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InMemoryPLM::open(temp_dir.path().join("join"))
        .await
        .unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    InMemorySetup { skm, plm }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_sign() -> InDiskSetup {
    let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = tempfile::Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join("join")).await.unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    InDiskSetup { skm, plm }
}

fn sign_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP sign only");

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_sign());
        let InMemorySetup { skm, plm } = setup_data;

        let counter = AtomicU64::new(0);
        let mut message = [0u8; 1];

        group.bench_function(BenchmarkId::new("sign_in_memory", ""), |b| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;
                for _ in 0..num_iters {
                    // Precomputation
                    let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                    let (id, cid) = FuturesExecutor
                        .block_on(DGSP::join(&skm.msk, &username, &plm))
                        .unwrap();
                    let seed_u = DGSP::keygen_user();
                    let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);
                    let mut certs = FuturesExecutor
                        .block_on(DGSP::req_cert(
                            &skm.msk,
                            id,
                            cid,
                            &wots_pks,
                            &plm,
                            &skm.spx_sk,
                        ))
                        .unwrap();
                    let wots_rand = wots_rands.pop().unwrap();
                    let cert = certs.pop().unwrap();
                    OsRng.fill_bytes(&mut message);

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    black_box(DGSP::sign(&message, &wots_rand, &seed_u, cert));

                    // Stop timer
                    total += start.elapsed();
                }
                total
            });
        });
    }

    #[cfg(feature = "in-disk")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_disk_sign());

        let InDiskSetup { sign_inputs } = setup_data;

        group.bench_function(
            BenchmarkId::new("sign_in_disk", format!("GROUP_SIZE={}", GROUP_SIZE)),
            |b| {
                b.iter(|| {
                    let data = sign_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(DGSP::sign(
                        &data.message,
                        &data.wots_rand,
                        &data.seed_u,
                        data.cert.clone(),
                    ));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, sign_benchmarks);
criterion_main!(benches);
