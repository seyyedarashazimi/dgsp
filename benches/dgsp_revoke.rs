use criterion::async_executor::AsyncExecutor;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId,
    Criterion,
};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP};
use dgsp::{PLMInterface, RevokedListInterface};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tempfile::Builder;

#[cfg(feature = "in-disk")]
use dgsp::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-memory")]
use dgsp::{InMemoryPLM, InMemoryRevokedList};

const CERTIFICATE_ISSUED_SIZE: usize = 1 << 0;
const GROUP_SIZE: usize = 1 << 10;

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
}

#[cfg(feature = "in-memory")]
async fn setup_in_memory_revoke() -> InMemorySetup {
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

    let (_, skm) = DGSP::keygen_manager().unwrap();

    InMemorySetup {
        skm,
        revoked_list,
        plm,
    }
}

#[cfg(feature = "in-disk")]
async fn setup_in_disk_revoke() -> InDiskSetup {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = Builder::new()
        .prefix("temp_example_db_")
        .tempdir_in(&project_root)
        .expect("Failed to create temporary directory in project root");

    let plm = InDiskPLM::open(temp_dir.path().join("join")).await.unwrap();
    let revoked_list = InDiskRevokedList::open(temp_dir.path().join("join"))
        .await
        .unwrap();

    let (_, skm) = DGSP::keygen_manager().unwrap();

    InDiskSetup {
        skm,
        revoked_list,
        plm,
    }
}

fn revoke_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DGSP revoke only");

    #[cfg(feature = "in-memory")]
    {
        let setup_data = FuturesExecutor.block_on(setup_in_memory_revoke());

        let InMemorySetup {
            skm,
            revoked_list,
            plm,
        } = setup_data;

        let counter = AtomicU64::new(0);

        group.bench_function(
            BenchmarkId::new(
                "revoke_in_memory",
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
                        let idx = counter.fetch_add(1, Ordering::Relaxed);
                        let username = format!("user_{}", idx);
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

                        // Check result for errors (optional)
                        result.expect("Revoke operation failed");
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
        } = setup_data;

        let counter = AtomicU64::new(0);

        group.bench_function(
            BenchmarkId::new(
                "revoke_in_disk",
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
                        let idx = counter.fetch_add(1, Ordering::Relaxed);
                        let username = format!("user_{}", idx);
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
                        let result = FuturesExecutor.block_on(DGSP::revoke(
                            &skm.msk,
                            &plm,
                            vec![id],
                            &revoked_list,
                        ));

                        // Stop timer
                        total += start.elapsed();

                        // Check result for errors (optional)
                        result.expect("Revoke operation failed");
                    }

                    total
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, revoke_benchmarks);
criterion_main!(benches);
