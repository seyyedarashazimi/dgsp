use crate::bench_utils::db_logical_size;
use criterion::async_executor::{AsyncExecutor, FuturesExecutor};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP};
use dgsp::PLMInterface;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;
#[cfg(feature = "in-disk")]
use tempfile::TempDir;

mod bench_utils;

const GROUP_SIZE: u64 = 1 << 10;
const KEEP_CREATED_DATABASES: bool = false;
static ALG_NAME: &str = "cert";

#[cfg(feature = "in-memory")]
pub struct InMemorySetup {
    pub skm: DGSPManagerSecretKey,
    pub plm: InMemoryPLM,
}

#[cfg(feature = "in-disk")]
pub struct InDiskSetup {
    pub skm: DGSPManagerSecretKey,
    pub plm: InDiskPLM,
    pub temp_dir: TempDir,
}

#[cfg(feature = "in-memory")]
pub async fn setup_in_memory_cert() -> InMemorySetup {
    let plm = InMemoryPLM::open("").await.unwrap();
    let (_, skm) = DGSP::keygen_manager().unwrap();

    // populate group with initial users
    for u in 0..GROUP_SIZE {
        DGSP::join(&skm.msk, &u.to_string(), &plm).await.unwrap();
    }

    InMemorySetup { skm, plm }
}

#[cfg(feature = "in-disk")]
pub async fn setup_in_disk_cert() -> InDiskSetup {
    let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = tempfile::Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join(ALG_NAME))
        .await
        .unwrap();
    let (_, skm) = DGSP::keygen_manager().unwrap();

    // populate group with initial users
    for u in 0..GROUP_SIZE {
        DGSP::join(&skm.msk, &u.to_string(), &plm).await.unwrap();
    }

    InDiskSetup { skm, plm, temp_dir }
}

fn cert_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("DGSP_{}", ALG_NAME));
    group.sample_size(10);

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_cert());
        let InMemorySetup { skm, plm } = setup_data;
        let counter = AtomicU64::new(GROUP_SIZE);

        group.bench_function(
            BenchmarkId::new(
                format!("{}_in_memory", ALG_NAME),
                format!("GROUP_SIZE={}", GROUP_SIZE),
            ),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;

                    // 1-time Precomputation
                    let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                    let (id, cid) = FuturesExecutor
                        .block_on(DGSP::join(&skm.msk, &username, &plm))
                        .unwrap();
                    let seed_u = DGSP::keygen_user();

                    for _ in 0..num_iters {
                        // Precomputation
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
        let InDiskSetup { skm, plm, temp_dir } = setup_data;
        let counter = AtomicU64::new(GROUP_SIZE);

        group.bench_function(
            BenchmarkId::new(
                format!("{}_in_disk", ALG_NAME),
                format!("GROUP_SIZE={}", GROUP_SIZE),
            ),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;

                    // 1-time Precomputation
                    let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                    let (id, cid) = FuturesExecutor
                        .block_on(DGSP::join(&skm.msk, &username, &plm))
                        .unwrap();
                    let seed_u = DGSP::keygen_user();

                    for _ in 0..num_iters {
                        // Precomputation
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
        let plm_usage = db_logical_size(&plm, &temp_dir, "PLM", ALG_NAME);
        println!("{}", plm_usage);

        // keep temp directory if requested
        if KEEP_CREATED_DATABASES {
            let _ = temp_dir.into_path();
        }
    }

    group.finish();
}

criterion_group!(benches, cert_benchmarks);
criterion_main!(benches);
