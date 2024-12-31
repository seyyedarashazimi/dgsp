use crate::bench_utils::format_size;
use criterion::async_executor::AsyncExecutor;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId,
    Criterion,
};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP};
#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;
use dgsp::PLMInterface;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;

mod bench_utils;

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
    temp_dir: TempDir,
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

    let plm = InDiskPLM::open(temp_dir.path().join("join")).await.unwrap();
    let (_, skm) = DGSP::keygen_manager().unwrap();
    InDiskSetup { skm, plm, temp_dir }
}

fn join_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP join only");

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_join());

        let InMemorySetup { skm, plm } = setup_data;

        let counter = AtomicUsize::new(0);

        group.bench_function(
            BenchmarkId::new("join_in_memory", format!("(GROUP_SIZE={})", GROUP_SIZE)),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;

                    for _ in 0..num_iters {
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
        // Report size:
        println!(
            "Approximate storage of InMemoryPLM: {}",
            format_size(plm.size_in_memory() as u64)
        );
    }

    #[cfg(feature = "in-disk")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_disk_join());

        let InDiskSetup { skm, plm, temp_dir } = setup_data;

        let counter = AtomicUsize::new(0);

        group.bench_function(
            BenchmarkId::new("join_in_disk", format!("(GROUP_SIZE={})", GROUP_SIZE)),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;

                    for _ in 0..num_iters {
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
        // Report size:
        println!(
            "Approximate storage of InDiskPLM in {:?}: {}",
            temp_dir,
            format_size(plm.size_in_disk().unwrap())
        );
    }

    group.finish();
}

criterion_group!(benches, join_benchmarks);
criterion_main!(benches);
