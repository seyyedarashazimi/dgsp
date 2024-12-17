#[cfg(feature = "in-disk")]
use dgsp::db::in_disk::PLM;
#[cfg(feature = "in-memory")]
use dgsp::db::in_memory::PLM;
use std::hint::black_box;

use dgsp::dgsp::DGSP;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};

fn main() {
    const SIGN_SIZE: u64 = 1 << 1;
    const GROUP_SIZE: u64 = 1 << 10;

    let mut plm = PLM::open().unwrap();
    let (_, sk_m, _) = DGSP::keygen_manager().unwrap();

    let usernames: Vec<String> = (1..=GROUP_SIZE).map(|i| format!("user_{}", i)).collect();

    let mut ids_cids = Vec::with_capacity(GROUP_SIZE as usize);

    for username in &usernames {
        ids_cids.push(DGSP::join(&sk_m.msk, username, &mut plm).unwrap());
    }

    let mut message = [0u8; 1];

    let mut results = Vec::with_capacity(SIGN_SIZE as usize);
    let mut elapsed_total_sign = Duration::new(0, 0);
    let mut elapsed_total_csr = Duration::new(0, 0);
    let mut elapsed_total_cert = Duration::new(0, 0);

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();
        OsRng.fill_bytes(&mut message);
        for _ in 0..SIGN_SIZE {
            let start_csr = Instant::now();
            let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);
            elapsed_total_csr += start_csr.elapsed();

            let start_cert = Instant::now();
            let mut certs =
                DGSP::req_cert(&sk_m.msk, id, cid, &wots_pks, &mut plm, &sk_m.spx_sk).unwrap();
            elapsed_total_cert += start_cert.elapsed();

            let wots_rand = wots_rands.pop().unwrap();
            let cert = certs.pop().unwrap();

            let start = Instant::now();
            let sig = DGSP::sign(&message, &wots_rand, &seed_u, cert);
            let elapsed = start.elapsed();

            results.push(black_box(sig));
            elapsed_total_sign += elapsed;
        }
    }
    println!(
        "Average Time for {} csr  for {} user: {:?}",
        SIGN_SIZE,
        GROUP_SIZE,
        elapsed_total_csr / (SIGN_SIZE * GROUP_SIZE) as u32
    );
    println!(
        "Average Time for {} cert for {} user: {:?}",
        SIGN_SIZE,
        GROUP_SIZE,
        elapsed_total_cert / (SIGN_SIZE * GROUP_SIZE) as u32
    );
    println!(
        "Average Time for {} sign for {} user: {:?}",
        SIGN_SIZE,
        GROUP_SIZE,
        elapsed_total_sign / (SIGN_SIZE * GROUP_SIZE) as u32
    );
}
