use crate::bench_utils::db_logical_size;
use criterion::async_executor::{AsyncExecutor, FuturesExecutor};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP};
use dgsp::{PLMInterface, RevokedListInterface};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "in-disk")]
use dgsp::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-memory")]
use dgsp::{InMemoryPLM, InMemoryRevokedList};
#[cfg(feature = "in-disk")]
use tempfile::TempDir;

mod bench_utils;

const GROUP_SIZE: u64 = 1 << 10;
const CERTIFICATE_ISSUED_SIZE: usize = 1 << 1;

const KEEP_CREATED_DATABASES: bool = true;

static ALG_NAME: &str = "revoke";

#[cfg(feature = "in-memory")]
struct InMemorySetup {
    skm: DGSPManagerSecretKey,
    revoked_list: InMemoryRevokedList,
    plm: InMemoryPLM,
}

#[cfg(feature = "in-disk")]
struct InDiskSetup {
    skm: DGSPManagerSecretKey,
    revoked_list: InDiskRevokedList,
    plm: InDiskPLM,
    temp_dir: TempDir,
}

#[cfg(feature = "in-memory")]
async fn setup_in_memory_revoke() -> InMemorySetup {
    let plm = InMemoryPLM::open("").await.unwrap();
    let revoked_list = InMemoryRevokedList::open("").await.unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    // populate group with initial users
    for u in 0..GROUP_SIZE {
        DGSP::join(&skm.msk, &u.to_string(), &plm).await.unwrap();
    }

    InMemorySetup {
        skm,
        revoked_list,
        plm,
    }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_revoke() -> InDiskSetup {
    let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = tempfile::Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join(ALG_NAME))
        .await
        .unwrap();
    let revoked_list = InDiskRevokedList::open(temp_dir.path().join(ALG_NAME))
        .await
        .unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    // populate group with initial users
    for u in 0..GROUP_SIZE {
        DGSP::join(&skm.msk, &u.to_string(), &plm).await.unwrap();
    }

    InDiskSetup {
        skm,
        revoked_list,
        plm,
        temp_dir,
    }
}

fn revoke_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("DGSP_{}", ALG_NAME));
    group.sample_size(10);

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_revoke());

        let InMemorySetup {
            skm,
            revoked_list,
            plm,
        } = setup_data;

        let counter = AtomicU64::new(GROUP_SIZE);

        group.bench_function(
            BenchmarkId::new(
                format!("{}_in_memory", ALG_NAME),
                format!(
                    "(GROUP_SIZE={}, CERTIFICATE_ISSUED_SIZE={})",
                    GROUP_SIZE, CERTIFICATE_ISSUED_SIZE
                ),
            ),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;

                    for _ in 0..num_iters {
                        // Precomputation
                        let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                        let (id, cid) = FuturesExecutor
                            .block_on(DGSP::join(&skm.msk, &username, &plm))
                            .unwrap();
                        let seed_u = DGSP::keygen_user();
                        let (wots_pks, _) =
                            DGSP::cert_sign_req_user(&seed_u, CERTIFICATE_ISSUED_SIZE);
                        black_box(
                            FuturesExecutor
                                .block_on(DGSP::req_cert(
                                    &skm.msk,
                                    id,
                                    cid,
                                    &wots_pks,
                                    &plm,
                                    &skm.spx_sk,
                                ))
                                .unwrap(),
                        );

                        // Start timer
                        let start = Instant::now();

                        // Revoke benchmark
                        let result = black_box(FuturesExecutor.block_on(DGSP::revoke(
                            &skm.msk,
                            &plm,
                            vec![id],
                            &revoked_list,
                        )));

                        // Stop timer
                        total += start.elapsed();

                        // Check result for errors
                        result.expect("Revoke failed");
                    }

                    total
                });
            },
        );
    }

    #[cfg(feature = "in-disk")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_disk_revoke());

        let InDiskSetup {
            skm,
            revoked_list,
            plm,
            temp_dir,
        } = setup_data;

        let counter = AtomicU64::new(GROUP_SIZE);

        group.bench_function(
            BenchmarkId::new(
                format!("{}_in_disk", ALG_NAME),
                format!(
                    "(GROUP_SIZE={}, CERTIFICATE_ISSUED_SIZE={})",
                    GROUP_SIZE, CERTIFICATE_ISSUED_SIZE
                ),
            ),
            |b| {
                b.iter_custom(|num_iters| {
                    let mut total = Duration::ZERO;

                    for _ in 0..num_iters {
                        // Precomputation
                        let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                        let (id, cid) = FuturesExecutor
                            .block_on(DGSP::join(&skm.msk, &username, &plm))
                            .unwrap();
                        let seed_u = DGSP::keygen_user();
                        let (wots_pks, _) =
                            DGSP::cert_sign_req_user(&seed_u, CERTIFICATE_ISSUED_SIZE);
                        black_box(
                            FuturesExecutor
                                .block_on(DGSP::req_cert(
                                    &skm.msk,
                                    id,
                                    cid,
                                    &wots_pks,
                                    &plm,
                                    &skm.spx_sk,
                                ))
                                .unwrap(),
                        );

                        // Start timer
                        let start = Instant::now();

                        // Revoke benchmark
                        let result = black_box(FuturesExecutor.block_on(DGSP::revoke(
                            &skm.msk,
                            &plm,
                            vec![id],
                            &revoked_list,
                        )));

                        // Stop timer
                        total += start.elapsed();

                        // Check result for errors
                        result.expect("Revocation failed");
                    }

                    total
                });
            },
        );
        let plm_usage = db_logical_size(&plm, &temp_dir, "PLM", ALG_NAME);
        println!("{}", plm_usage);

        let revoked_list_usage = db_logical_size(&plm, &temp_dir, "RevokedList", ALG_NAME);
        println!("{}", revoked_list_usage);

        if KEEP_CREATED_DATABASES {
            let _ = temp_dir.into_path();
        }
    }

    group.finish();
}

criterion_group!(benches, revoke_benchmarks);
criterion_main!(benches);
