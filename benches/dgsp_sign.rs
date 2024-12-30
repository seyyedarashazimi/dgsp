use criterion::async_executor::AsyncExecutor;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId,
    Criterion,
};
use dgsp::dgsp::{DGSPWotsRand, DGSP};
use dgsp::PLMInterface;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};

use dgsp::params::DGSP_POS_BYTES;
use dgsp::sphincs_plus::{SphincsPlusSignature, SPX_N};
#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;

const GROUP_SIZE: usize = 1 << 10;

struct SignData {
    message: Vec<u8>,
    wots_rand: DGSPWotsRand,
    seed_u: [u8; SPX_N],
    cert: ([u8; DGSP_POS_BYTES], SphincsPlusSignature),
}

#[cfg(feature = "in-memory")]
struct InMemorySetup {
    sign_inputs: Vec<SignData>,
}

#[cfg(feature = "in-disk")]
struct InDiskSetup {
    sign_inputs: Vec<SignData>,
}

#[cfg(feature = "in-memory")]
async fn setup_in_memory_sign() -> InMemorySetup {
    let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = tempfile::Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InMemoryPLM::open(temp_dir.path().join("join"))
        .await
        .unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    let usernames: Vec<String> = (1..=GROUP_SIZE).map(|i| format!("user_{}", i)).collect();
    let mut ids_cids = Vec::with_capacity(GROUP_SIZE);

    for username in &usernames {
        let (id, cid) = DGSP::join(&skm.msk, username, &plm).await.unwrap();
        ids_cids.push((id, cid));
    }

    let mut sign_inputs = Vec::new();

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();

        let mut message = [0u8; 1];
        OsRng.fill_bytes(&mut message);

        let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);
        let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk)
            .await
            .unwrap();

        let wots_rand = wots_rands.pop().unwrap();
        let cert = certs.pop().unwrap();

        sign_inputs.push(SignData {
            message: message.to_vec(),
            wots_rand,
            seed_u,
            cert,
        });
    }

    InMemorySetup { sign_inputs }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_sign() -> InDiskSetup {
    let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = tempfile::Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join("join")).await.unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    let usernames: Vec<String> = (1..=GROUP_SIZE).map(|i| format!("user_{}", i)).collect();
    let mut ids_cids = Vec::with_capacity(GROUP_SIZE);

    for username in &usernames {
        let (id, cid) = DGSP::join(&skm.msk, username, &plm).await.unwrap();
        ids_cids.push((id, cid));
    }

    let mut sign_inputs = Vec::new();

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();

        let mut message = [0u8; 1];
        OsRng.fill_bytes(&mut message);

        let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);
        let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk)
            .await
            .unwrap();

        let wots_rand = wots_rands.pop().unwrap();
        let cert = certs.pop().unwrap();

        sign_inputs.push(SignData {
            message: message.to_vec(),
            wots_rand,
            seed_u,
            cert,
        });
    }

    InDiskSetup { sign_inputs }
}

fn sign_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP sign only");

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_sign());

        let InMemorySetup { sign_inputs } = setup_data;

        group.bench_function(
            BenchmarkId::new("sign_in_memory", format!("GROUP_SIZE={}", GROUP_SIZE)),
            |b| {
                b.iter(|| {
                    let data = sign_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(DGSP::sign(
                        &data.message,
                        &data.wots_rand,
                        &data.seed_u,
                        data.cert.clone(),
                    ));
                });
            },
        );
    }

    #[cfg(feature = "in-disk")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_disk_sign());

        let InDiskSetup { sign_inputs } = setup_data;

        group.bench_function(
            BenchmarkId::new("sign_in_disk", format!("GROUP_SIZE={}", GROUP_SIZE)),
            |b| {
                b.iter(|| {
                    let data = sign_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(DGSP::sign(
                        &data.message,
                        &data.wots_rand,
                        &data.seed_u,
                        data.cert.clone(),
                    ));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, sign_benchmarks);
criterion_main!(benches);
