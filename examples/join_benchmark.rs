use dgsp::PLMInterface;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tempfile::Builder;

use dgsp::dgsp::DGSP;
#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;

const GROUP_SIZE: u64 = 1 << 20;

#[cfg(feature = "in-memory")]
async fn join_in_memory_benchmark() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InMemoryPLM::open(temp_dir.path().join("join"))
        .await
        .unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    let mut results = Vec::with_capacity(GROUP_SIZE as usize);
    let mut elapsed_total = Duration::new(0, 0);

    for i in 1..=GROUP_SIZE {
        let username = format!("user_{}", i);
        let start = Instant::now();
        let result = DGSP::join(&skm.msk, username.as_str(), &plm).await.unwrap();
        let elapsed = start.elapsed();
        elapsed_total += elapsed;

        results.push(black_box(result));
    }

    println!(
        "Average Time for {} join calls in memory: {:?}",
        GROUP_SIZE,
        elapsed_total / (GROUP_SIZE as u32)
    );
}

#[cfg(feature = "in-disk")]
async fn join_in_disk_benchmark() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join("join")).await.unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    let mut results = Vec::with_capacity(GROUP_SIZE as usize);
    let mut elapsed_total = Duration::new(0, 0);

    for i in 1..=GROUP_SIZE {
        let username = format!("user_{}", i);
        let start = Instant::now();
        let result = DGSP::join(&skm.msk, username.as_str(), &plm).await.unwrap();
        let elapsed = start.elapsed();
        elapsed_total += elapsed;

        results.push(black_box(result));
    }

    println!(
        "Average Time for {} join calls in disk: {:?}",
        GROUP_SIZE,
        elapsed_total / (GROUP_SIZE as u32)
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    #[cfg(feature = "in-memory")]
    join_in_memory_benchmark().await;

    #[cfg(feature = "in-disk")]
    join_in_disk_benchmark().await;
}
