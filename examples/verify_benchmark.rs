use dgsp::dgsp::DGSP;
use dgsp::{PLMInterface, RevokedListInterface};
use rand::rngs::OsRng;
use rand::RngCore;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tempfile::Builder;

#[cfg(feature = "in-disk")]
use dgsp::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-memory")]
use dgsp::{InMemoryPLM, InMemoryRevokedList};

const SIGN_SIZE: u64 = 1 << 0;
const GROUP_SIZE: u64 = 1 << 10;

#[cfg(feature = "in-memory")]
async fn verify_in_memory_benchmark() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InMemoryPLM::open(temp_dir.path().join("join"))
        .await
        .unwrap();

    let revoked_list = InMemoryRevokedList::open(temp_dir.path().join("join"))
        .await
        .unwrap();

    let (pkm, skm) = DGSP::keygen_manager().unwrap();

    let usernames: Vec<String> = (1..=GROUP_SIZE).map(|i| format!("user_{}", i)).collect();

    let mut ids_cids = Vec::with_capacity(GROUP_SIZE as usize);

    for username in &usernames {
        ids_cids.push(DGSP::join(&skm.msk, username, &plm).await.unwrap());
    }

    let mut message = [0u8; 1];

    let mut elapsed_total = Duration::new(0, 0);

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();
        OsRng.fill_bytes(&mut message);
        for _ in 0..SIGN_SIZE {
            let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);

            let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk)
                .await
                .unwrap();

            let wots_rand = wots_rands.pop().unwrap();
            let cert = certs.pop().unwrap();

            let sig = DGSP::sign(&message, &wots_rand, &seed_u, cert);

            let start = Instant::now();
            black_box(DGSP::verify(&message, &sig, &revoked_list, &pkm).await).unwrap();
            let elapsed = start.elapsed();
            elapsed_total += elapsed;
        }
    }
    println!(
        "Average Time for {} verify for {} user in memory: {:?}",
        SIGN_SIZE,
        GROUP_SIZE,
        elapsed_total / (SIGN_SIZE * GROUP_SIZE) as u32
    );
}

#[cfg(feature = "in-disk")]
async fn verify_in_disk_benchmark() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join("join")).await.unwrap();

    let revoked_list = InDiskRevokedList::open(temp_dir.path().join("join"))
        .await
        .unwrap();

    let (pkm, skm) = DGSP::keygen_manager().unwrap();

    let usernames: Vec<String> = (1..=GROUP_SIZE).map(|i| format!("user_{}", i)).collect();

    let mut ids_cids = Vec::with_capacity(GROUP_SIZE as usize);

    for username in &usernames {
        ids_cids.push(DGSP::join(&skm.msk, username, &plm).await.unwrap());
    }

    let mut message = [0u8; 1];

    let mut elapsed_total = Duration::new(0, 0);

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();
        OsRng.fill_bytes(&mut message);
        for _ in 0..SIGN_SIZE {
            let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);

            let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk)
                .await
                .unwrap();

            let wots_rand = wots_rands.pop().unwrap();
            let cert = certs.pop().unwrap();

            let sig = DGSP::sign(&message, &wots_rand, &seed_u, cert);

            let start = Instant::now();
            black_box(DGSP::verify(&message, &sig, &revoked_list, &pkm).await).unwrap();
            let elapsed = start.elapsed();
            elapsed_total += elapsed;
        }
    }
    println!(
        "Average Time for {} verify for {} user in disk: {:?}",
        SIGN_SIZE,
        GROUP_SIZE,
        elapsed_total / (SIGN_SIZE * GROUP_SIZE) as u32
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    #[cfg(feature = "in-memory")]
    verify_in_memory_benchmark().await;

    #[cfg(feature = "in-disk")]
    verify_in_disk_benchmark().await;
}
