use crate::bench_utils::{disk_usage, format_size};
use criterion::async_executor::{AsyncExecutor, FuturesExecutor};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP};
use dgsp::PLMInterface;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;
#[cfg(feature = "in-disk")]
use tempfile::TempDir;

mod bench_utils;

const GROUP_SIZE: u64 = 1 << 10;

// Set the following to be true if you want to keep the temporarily-created databases
// for further inspections.
const KEEP_CREATED_DATABASES: bool = false;

static ALG_NAME: &str = "join";

static ONCE: std::sync::Once = std::sync::Once::new();

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
async fn setup_in_memory_join() -> InMemorySetup {
    let plm = InMemoryPLM::open("").await.unwrap();
    let (_, skm) = DGSP::keygen_manager().unwrap();
    InMemorySetup { skm, plm }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_join() -> InDiskSetup {
    let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = tempfile::Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join(ALG_NAME))
        .await
        .unwrap();
    let (_, skm) = DGSP::keygen_manager().unwrap();
    InDiskSetup { skm, plm, temp_dir }
}

fn join_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("DGSP_{}", ALG_NAME));
    group.sample_size(10);

    #[cfg(feature = "in-memory")]
    {
        group.bench_function(
            BenchmarkId::new(
                format!("{}_in_memory", ALG_NAME),
                format!("GROUP_SIZE={}", GROUP_SIZE),
            ),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;

                    for _ in 0..num_iters {
                        let setup_data = FuturesExecutor.block_on(setup_in_memory_join());
                        let InMemorySetup { skm, plm } = setup_data;
                        let counter = AtomicUsize::new(0);
                        for _ in 0..GROUP_SIZE {
                            // Precomputation
                            let username = counter.fetch_add(1, Ordering::Relaxed).to_string();

                            // Start timer
                            let start = Instant::now();

                            // Benchmark
                            black_box(
                                FuturesExecutor
                                    .block_on(DGSP::join(&skm.msk, &username, &plm))
                                    .unwrap(),
                            );

                            // Stop timer
                            total += start.elapsed();
                        }
                    }
                    let nanos_total = total.as_nanos() as f64;
                    let avg_nanos = nanos_total / GROUP_SIZE as f64;

                    let avg_nanos_ceil = avg_nanos.max(1.0).round() as u64;
                    Duration::from_nanos(avg_nanos_ceil)
                });
            },
        );
    }

    #[cfg(feature = "in-disk")]
    {
        // let size_reported = AtomicBool::new(true);
        let mut usage = 0u64;
        group.bench_function(
            BenchmarkId::new(
                format!("{}_in_disk", ALG_NAME),
                format!("(GROUP_SIZE={})", GROUP_SIZE),
            ),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;

                    for _ in 0..num_iters {
                        let setup_data = FuturesExecutor.block_on(setup_in_disk_join());
                        let InDiskSetup { skm, plm, temp_dir } = setup_data;
                        let counter = AtomicUsize::new(0);
                        for _ in 0..GROUP_SIZE {
                            // Precomputation
                            let username = counter.fetch_add(1, Ordering::Relaxed).to_string();

                            // Start timer
                            let start = Instant::now();

                            // Benchmark
                            black_box(
                                FuturesExecutor
                                    .block_on(DGSP::join(&skm.msk, &username, &plm))
                                    .unwrap(),
                            );

                            // Stop timer
                            total += start.elapsed();
                        }

                        // get storage stats once
                        ONCE.call_once(|| {
                            usage = disk_usage(&temp_dir).unwrap();
                            black_box(&temp_dir);

                            if KEEP_CREATED_DATABASES {
                                let _ = temp_dir.into_path();
                            }
                        });
                    }
                    let nanos_total = total.as_nanos() as f64;
                    let avg_nanos = nanos_total / GROUP_SIZE as f64;

                    let avg_nanos_ceil = avg_nanos.max(1.0).round() as u64;
                    Duration::from_nanos(avg_nanos_ceil)
                });
            },
        );
        println!(
            "Approximate logical size of PLM in DGSP {}: {}",
            ALG_NAME,
            format_size(usage)
        );
    }

    group.finish();
}

criterion_group!(benches, join_benchmarks);
criterion_main!(benches);
