#[cfg(feature = "in-disk")]
use dgsp::db::in_disk::PLM;
#[cfg(feature = "in-memory")]
use dgsp::db::in_memory::PLM;

use dgsp::dgsp::DGSP;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};

fn main() {
    const SIGN_SIZE: u64 = 1 << 1;
    const GROUP_SIZE: u64 = 1 << 10;

    let mut plm = PLM::open().unwrap();
    let (pk_m, sk_m, revoked_list) = DGSP::keygen_manager().unwrap();

    let usernames: Vec<String> = (1..=GROUP_SIZE).map(|i| format!("user_{}", i)).collect();

    let mut ids_cids = Vec::with_capacity(GROUP_SIZE as usize);

    for username in &usernames {
        ids_cids.push(DGSP::join(&sk_m.msk, username, &mut plm).unwrap());
    }

    let mut message = [0u8; 1];

    let mut elapsed_total = Duration::new(0, 0);

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();
        OsRng.fill_bytes(&mut message);
        for _ in 0..SIGN_SIZE {
            let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);

            let mut certs =
                DGSP::req_cert(&sk_m.msk, id, cid, &wots_pks, &mut plm, &sk_m.spx_sk).unwrap();

            let wots_rand = wots_rands.pop().unwrap();
            let cert = certs.pop().unwrap();

            let sig = DGSP::sign(&message, &wots_rand, &seed_u, cert);

            let start = Instant::now();
            DGSP::verify(&message, &sig, &revoked_list, &pk_m).unwrap();
            let elapsed = start.elapsed();
            elapsed_total += elapsed;
        }
    }
    println!(
        "Average Time for {} verify for {} user: {:?}",
        SIGN_SIZE,
        GROUP_SIZE,
        elapsed_total / (SIGN_SIZE * GROUP_SIZE) as u32
    );
}
