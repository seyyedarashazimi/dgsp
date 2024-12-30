use criterion::async_executor::AsyncExecutor;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId,
    Criterion,
};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSPSignature, DGSP};
use dgsp::PLMInterface;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};
use std::path::PathBuf;
use tempfile::Builder;

#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;

const GROUP_SIZE: usize = 1 << 10;

struct OpenData {
    signature: DGSPSignature,
}

#[cfg(feature = "in-memory")]
struct InMemorySetup {
    skm: DGSPManagerSecretKey,
    plm: InMemoryPLM,
    open_inputs: Vec<OpenData>,
}

#[cfg(feature = "in-disk")]
struct InDiskSetup {
    skm: DGSPManagerSecretKey,
    plm: InDiskPLM,
    open_inputs: Vec<OpenData>,
}

#[cfg(feature = "in-memory")]
async fn setup_in_memory_open() -> InMemorySetup {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
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

    let mut open_inputs = Vec::with_capacity(GROUP_SIZE);

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

        let sig = DGSP::sign(&message, &wots_rand, &seed_u, cert);

        open_inputs.push(OpenData { signature: sig });
    }

    InMemorySetup {
        skm,
        plm,
        open_inputs,
    }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_open() -> InDiskSetup {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
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

    let mut open_inputs = Vec::with_capacity(GROUP_SIZE);

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

        let sig = DGSP::sign(&message, &wots_rand, &seed_u, cert);

        open_inputs.push(OpenData { signature: sig });
    }

    InDiskSetup {
        skm,
        plm,
        open_inputs,
    }
}

fn open_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP open only");

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_open());

        let InMemorySetup {
            skm,
            plm,
            open_inputs,
        } = setup_data;

        group.bench_function(
            BenchmarkId::new("open_in_memory", format!("GROUP_SIZE={}", GROUP_SIZE)),
            |b| {
                b.to_async(FuturesExecutor).iter(|| async {
                    let data = open_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(DGSP::open(&skm.msk, &plm, &data.signature).await.unwrap());
                });
            },
        );
    }

    #[cfg(feature = "in-disk")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_disk_open());

        let InDiskSetup {
            skm,
            plm,
            open_inputs,
        } = setup_data;

        group.bench_function(
            BenchmarkId::new("open_in_disk", format!("GROUP_SIZE={}", GROUP_SIZE)),
            |b| {
                b.to_async(FuturesExecutor).iter(|| async {
                    let data = open_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(DGSP::open(&skm.msk, &plm, &data.signature).await.unwrap());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, open_benchmarks);
criterion_main!(benches);
