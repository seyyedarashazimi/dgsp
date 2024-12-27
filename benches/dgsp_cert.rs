use criterion::async_executor::AsyncExecutor;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId,
    Criterion,
};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP};
use dgsp::PLMInterface;
use rand::seq::SliceRandom;
use rand::thread_rng;

use dgsp::params::DGSP_N;
use dgsp::sphincs_plus::SPX_WOTS_PK_BYTES;
#[cfg(feature = "in-disk")]
use dgsp::InDiskPLM;
#[cfg(feature = "in-memory")]
use dgsp::InMemoryPLM;

const SIGN_SIZE: usize = 1 << 0;
const GROUP_SIZE: usize = 1 << 10;

struct CertData {
    id: u64,
    cid: [u8; DGSP_N],
    pk_wots: Vec<[u8; SPX_WOTS_PK_BYTES]>,
}

#[cfg(feature = "in-memory")]
struct InMemorySetup {
    cert_inputs: Vec<CertData>,
    skm: DGSPManagerSecretKey,
    plm: InMemoryPLM,
}

#[cfg(feature = "in-disk")]
struct InDiskSetup {
    cert_inputs: Vec<CertData>,
    skm: DGSPManagerSecretKey,
    plm: InDiskPLM,
}

#[cfg(feature = "in-memory")]
async fn setup_in_memory_cert() -> InMemorySetup {
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

    let mut cert_inputs = Vec::new();

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();

        let (wots_pks, _) = DGSP::cert_sign_req_user(&seed_u, SIGN_SIZE);
        for _ in 0..SIGN_SIZE {
            cert_inputs.push(CertData {
                id,
                cid,
                pk_wots: wots_pks.clone(),
            });
        }
    }

    InMemorySetup {
        cert_inputs,
        skm,
        plm,
    }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_cert() -> InDiskSetup {
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

    let mut cert_inputs = Vec::new();

    for (id, cid) in ids_cids {
        let seed_u = DGSP::keygen_user();

        let (wots_pks, _) = DGSP::cert_sign_req_user(&seed_u, SIGN_SIZE);
        for _ in 0..SIGN_SIZE {
            cert_inputs.push(CertData {
                id,
                cid,
                pk_wots: wots_pks.clone(),
            });
        }
    }

    InDiskSetup {
        cert_inputs,
        skm,
        plm,
    }
}

fn cert_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP cert only");

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_cert());

        let InMemorySetup {
            cert_inputs,
            skm,
            plm,
        } = setup_data;

        group.bench_function(
            BenchmarkId::new(
                "cert_in_memory",
                format!("(SIGN_SIZE={}, GROUP_SIZE={})", SIGN_SIZE, GROUP_SIZE),
            ),
            |b| {
                b.to_async(FuturesExecutor).iter(|| async {
                    let data = cert_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(
                        DGSP::req_cert(
                            &skm.msk,
                            data.id,
                            data.cid,
                            &data.pk_wots,
                            &plm,
                            &skm.spx_sk,
                        )
                        .await
                        .unwrap(),
                    );
                });
            },
        );
    }

    #[cfg(feature = "in-disk")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_disk_cert());

        let InDiskSetup {
            cert_inputs,
            skm,
            plm,
        } = setup_data;

        group.bench_function(
            BenchmarkId::new(
                "cert_in_disk",
                format!("(SIGN_SIZE={}, GROUP_SIZE={})", SIGN_SIZE, GROUP_SIZE),
            ),
            |b| {
                b.to_async(FuturesExecutor).iter(|| async {
                    let data = cert_inputs.choose(&mut thread_rng()).unwrap();
                    black_box(
                        DGSP::req_cert(
                            &skm.msk,
                            data.id,
                            data.cid,
                            &data.pk_wots,
                            &plm,
                            &skm.spx_sk,
                        )
                        .await
                        .unwrap(),
                    );
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, cert_benchmarks);
criterion_main!(benches);
