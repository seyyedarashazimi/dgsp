#[cfg(feature = "in-disk")]
use dgsp::db::in_disk::PLM;
#[cfg(feature = "in-memory")]
use dgsp::db::in_memory::PLM;

use dgsp::dgsp::DGSP;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    const GROUP_SIZE: u64 = 1 << 10;
    let mut plm = PLM::open().unwrap();
    let (_, sk_m, _) = DGSP::keygen_manager().unwrap();

    let mut results = Vec::with_capacity(GROUP_SIZE as usize);

    let usernames: Vec<String> = (1..=GROUP_SIZE).map(|i| format!("user_{}", i)).collect();

    let start = Instant::now();
    for username in &usernames {
        let result = DGSP::join(&sk_m.msk, username, &mut plm).unwrap();
        results.push(black_box(result));
    }
    let elapsed = start.elapsed();
    println!(
        "Time for {} join calls: {:?}",
        GROUP_SIZE,
        elapsed / (GROUP_SIZE as u32)
    );
}
