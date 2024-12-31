use criterion::async_executor::AsyncExecutor;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId,
    Criterion,
};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP};
use dgsp::PLMInterface;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;

const GROUP_SIZE: usize = 1 << 10;

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
async fn setup_in_memory_cert() -> InMemorySetup {
    let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = tempfile::Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InMemoryPLM::open(temp_dir.path().join("join"))
        .await
        .unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    // populate group with initial users
    for u in 0..GROUP_SIZE {
        DGSP::join(&skm.msk, &u.to_string(), &plm).await.unwrap();
    }

    InMemorySetup { skm, plm }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_cert() -> InDiskSetup {
    let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = tempfile::Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join("join")).await.unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    // populate group with initial users
    for u in 0..GROUP_SIZE {
        DGSP::join(&skm.msk, &u.to_string(), &plm).await.unwrap();
    }

    InDiskSetup { skm, plm }
}

fn cert_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP cert only");

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_cert());
        let InMemorySetup { skm, plm } = setup_data;
        let counter = AtomicU64::new(GROUP_SIZE as u64);

        group.bench_function(
            BenchmarkId::new("cert_in_memory", format!("GROUP_SIZE={}", GROUP_SIZE)),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..num_iters {
                        // Precomputation
                        let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                        let (id, cid) = FuturesExecutor
                            .block_on(DGSP::join(&skm.msk, &username, &plm))
                            .unwrap();
                        let seed_u = DGSP::keygen_user();
                        let (wots_pks, _) = DGSP::cert_sign_req_user(&seed_u, 1);

                        // Start timer
                        let start = Instant::now();

                        // Benchmark
                        black_box(
                            FuturesExecutor
                                .block_on(DGSP::req_cert(
                                    &skm.msk,
                                    id,
                                    cid,
                                    &wots_pks,
                                    &plm,
                                    &skm.spx_sk,
                                ))
                                .unwrap(),
                        );

                        // Stop timer
                        total += start.elapsed();
                    }
                    total
                });
            },
        );
    }

    #[cfg(feature = "in-disk")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_disk_cert());
        let InDiskSetup { skm, plm } = setup_data;
        let counter = AtomicU64::new(GROUP_SIZE as u64);

        group.bench_function(
            BenchmarkId::new("cert_in_disk", format!("GROUP_SIZE={}", GROUP_SIZE)),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..num_iters {
                        // Precomputation
                        let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                        let (id, cid) = FuturesExecutor
                            .block_on(DGSP::join(&skm.msk, &username, &plm))
                            .unwrap();
                        let seed_u = DGSP::keygen_user();
                        let (wots_pks, _) = DGSP::cert_sign_req_user(&seed_u, 1);

                        // Start timer
                        let start = Instant::now();

                        // Benchmark
                        black_box(
                            FuturesExecutor
                                .block_on(DGSP::req_cert(
                                    &skm.msk,
                                    id,
                                    cid,
                                    &wots_pks,
                                    &plm,
                                    &skm.spx_sk,
                                ))
                                .unwrap(),
                        );

                        // Stop timer
                        total += start.elapsed();
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, cert_benchmarks);
criterion_main!(benches);
