use criterion::async_executor::AsyncExecutor;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId,
    Criterion,
};
use dgsp::dgsp::{DGSPManagerPublicKey, DGSPSignature, DGSP};
use dgsp::{PLMInterface, RevokedListInterface};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};
use std::path::PathBuf;
use tempfile::Builder;

#[cfg(feature = "in-disk")]
use dgsp::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-memory")]
use dgsp::{InMemoryPLM, InMemoryRevokedList};

const SIGN_SIZE: usize = 1 << 0;
const GROUP_SIZE: usize = 1 << 10;

struct VerifyData {
    message: Vec<u8>,
    signature: DGSPSignature,
}

#[cfg(feature = "in-memory")]
struct InMemorySetup {
    pkm: DGSPManagerPublicKey,
    revoked_list: InMemoryRevokedList,
    verify_inputs: Vec<VerifyData>,
}

#[cfg(feature = "in-disk")]
struct InDiskSetup {
    pkm: DGSPManagerPublicKey,
    revoked_list: InDiskRevokedList,
    verify_inputs: Vec<VerifyData>,
}

#[cfg(feature = "in-memory")]
async fn setup_in_memory_verify() -> InMemorySetup {
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
    let mut ids_cids = Vec::with_capacity(GROUP_SIZE);

    for username in &usernames {
        let (id, cid) = DGSP::join(&skm.msk, username, &plm).await.unwrap();
        ids_cids.push((id, cid));
    }

    let mut verify_inputs = Vec::with_capacity(GROUP_SIZE * SIGN_SIZE);

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();

        let mut message = [0u8; 1];
        OsRng.fill_bytes(&mut message);

        let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, SIGN_SIZE);
        let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk)
            .await
            .unwrap();

        for _ in 0..SIGN_SIZE {
            let wots_rand = wots_rands.pop().unwrap();
            let cert = certs.pop().unwrap();

            let sig = DGSP::sign(&message, &wots_rand, &seed_u, cert);

            verify_inputs.push(VerifyData {
                message: message.to_vec(),
                signature: sig,
            });
        }
    }

    InMemorySetup {
        pkm,
        revoked_list,
        verify_inputs,
    }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_verify() -> InDiskSetup {
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
    let mut ids_cids = Vec::with_capacity(GROUP_SIZE);

    for username in &usernames {
        let (id, cid) = DGSP::join(&skm.msk, username, &plm).await.unwrap();
        ids_cids.push((id, cid));
    }

    let mut verify_inputs = Vec::with_capacity(GROUP_SIZE * SIGN_SIZE);

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();
        let mut message = [0u8; 1];
        OsRng.fill_bytes(&mut message);

        let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, SIGN_SIZE);
        let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk)
            .await
            .unwrap();

        for _ in 0..SIGN_SIZE {
            let wots_rand = wots_rands.pop().unwrap();
            let cert = certs.pop().unwrap();

            let sig = DGSP::sign(&message, &wots_rand, &seed_u, cert);

            verify_inputs.push(VerifyData {
                message: message.to_vec(),
                signature: sig,
            });
        }
    }

    InDiskSetup {
        pkm,
        revoked_list,
        verify_inputs,
    }
}

fn verify_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP verify only");

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_verify());

        let InMemorySetup {
            pkm,
            revoked_list,
            verify_inputs,
        } = setup_data;

        group.bench_function(
            BenchmarkId::new(
                "verify_in_memory",
                format!("(SIGN_SIZE={}, GROUP_SIZE={})", SIGN_SIZE, GROUP_SIZE),
            ),
            |b| {
                b.to_async(FuturesExecutor).iter(|| async {
                    let data = verify_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(
                        DGSP::verify(&data.message, &data.signature, &revoked_list, &pkm).await,
                    )
                    .unwrap();
                });
            },
        );
    }

    #[cfg(feature = "in-disk")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_disk_verify());

        let InDiskSetup {
            pkm,
            revoked_list,
            verify_inputs,
        } = setup_data;

        use rand::seq::SliceRandom;
        use rand::thread_rng;

        group.bench_function(
            BenchmarkId::new(
                "verify_in_disk",
                format!("(SIGN_SIZE={}, GROUP_SIZE={})", SIGN_SIZE, GROUP_SIZE),
            ),
            |b| {
                b.to_async(FuturesExecutor).iter(|| async {
                    let data = verify_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(
                        DGSP::verify(&data.message, &data.signature, &revoked_list, &pkm).await,
                    )
                    .unwrap();
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, verify_benchmarks);
criterion_main!(benches);
