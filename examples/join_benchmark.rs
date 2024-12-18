#[cfg(feature = "in-disk")]
use dgsp::db::in_disk::PLM;
#[cfg(feature = "in-memory")]
use dgsp::db::in_memory::PLM;

use dgsp::dgsp::DGSP;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tempfile::Builder;

fn main() {
    const GROUP_SIZE: u64 = 1 << 10;

    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = PLM::open_with_path(temp_dir.path().join("join")).unwrap();
    let (_, sk_m, _) = DGSP::keygen_manager(temp_dir.path().join("join")).unwrap();

    let mut results = Vec::with_capacity(GROUP_SIZE as usize);
    let mut elapsed_total = Duration::new(0, 0);

    for i in 1..=GROUP_SIZE {
        let username = format!("user_{}", i);
        let start = Instant::now();
        let result = DGSP::join(&sk_m.msk, username.as_str(), &plm).unwrap();
        let elapsed = start.elapsed();
        elapsed_total += elapsed;

        results.push(black_box(result));
    }

    println!(
        "Average Time for {} join calls: {:?}",
        GROUP_SIZE,
        elapsed_total / (GROUP_SIZE as u32)
    );
}
