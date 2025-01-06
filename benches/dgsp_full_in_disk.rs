#![cfg(feature = "in-disk")]

use criterion::async_executor::{AsyncExecutor, FuturesExecutor};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP, DGSPMSK};
use dgsp::params::DGSP_N;
use dgsp::InDiskPLM;
use dgsp::{InDiskRevokedList, PLMInterface, RevokedListInterface};
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::ThreadPoolBuilder;
use sled::Transactional;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

mod bench_utils;

const MSK: [u8; DGSP_N] = [170_u8; DGSP_N];
const GROUP_SIZE: u64 = 1 << 21;
const CERTIFICATE_ISSUED_SIZE: usize = 1 << 4; // batch size
const TWEAK_USERS_SIZE: u64 = 10;

fn path() -> PathBuf {
    PathBuf::from(format!(
        "dgsp_{}_with_{}_users",
        detect_spx_feature(),
        GROUP_SIZE
    ))
}

fn detect_spx_feature() -> &'static str {
    let active_features = [
        ("sphincs_sha2_128f", cfg!(feature = "sphincs_sha2_128f")),
        ("sphincs_sha2_128s", cfg!(feature = "sphincs_sha2_128s")),
        ("sphincs_sha2_192f", cfg!(feature = "sphincs_sha2_192f")),
        ("sphincs_sha2_192s", cfg!(feature = "sphincs_sha2_192s")),
        ("sphincs_sha2_256f", cfg!(feature = "sphincs_sha2_256f")),
        ("sphincs_sha2_256s", cfg!(feature = "sphincs_sha2_256s")),
        ("sphincs_shake_128f", cfg!(feature = "sphincs_shake_128f")),
        ("sphincs_shake_128s", cfg!(feature = "sphincs_shake_128s")),
        ("sphincs_shake_192f", cfg!(feature = "sphincs_shake_192f")),
        ("sphincs_shake_192s", cfg!(feature = "sphincs_shake_192s")),
        ("sphincs_shake_256f", cfg!(feature = "sphincs_shake_256f")),
        ("sphincs_shake_256s", cfg!(feature = "sphincs_shake_256s")),
    ];

    let active: Vec<_> = active_features
        .iter()
        .filter(|(_, active)| *active)
        .collect();

    match active.len() {
        0 => panic!("No SPHINCS+ feature is active. Exactly one feature must be enabled."),
        1 => active[0].0,
        _ => panic!("Multiple SPHINCS+ features are active. Only one feature must be enabled."),
    }
}

async fn initialize_plm_with_users() -> InDiskPLM {
    let path = path();
    let db_preloaded = path.join("plm").exists();

    let plm = InDiskPLM::open(path).await.unwrap();

    if !db_preloaded {
        // populate group with initial users in parallel
        let tasks = (0..GROUP_SIZE).map(|u| {
            let plm_ref = &plm;
            async move {
                DGSP::join(&DGSPMSK::from(MSK), &u.to_string(), plm_ref)
                    .await
                    .unwrap();
            }
        });
        futures::future::join_all(tasks).await;
    }

    plm
}

fn reset_plm(plm: &InDiskPLM) {
    plm.flush().unwrap();
    let plme_tree = plm.open_tree("plme_tree").unwrap();
    let name_tree = plm.open_tree("name_tree").unwrap();
    let meta_tree = plm.open_tree("meta_tree").unwrap();
    (&plme_tree, &name_tree, &meta_tree)
        .transaction(|(ptree, ntree, mtree)| {
            let next_id = match mtree.get(b"__next_id")? {
                Some(id_bytes) => u64::from_be_bytes(id_bytes.as_ref().try_into().unwrap()),
                None => 0u64,
            };

            (GROUP_SIZE..next_id).try_for_each(|u| {
                ptree.remove(&u.to_be_bytes())?;
                ntree.remove(u.to_string().as_bytes())?;
                mtree.insert(b"__next_id", &GROUP_SIZE.to_be_bytes())?;

                Ok::<(), sled::transaction::ConflictableTransactionError>(())
            })?;

            Ok(())
        })
        .unwrap();
}

fn delete_revoked_list(revoked_list: InDiskRevokedList) {
    let path = path();
    revoked_list.flush().unwrap();
    if path.join("rl").exists() {
        fs::remove_dir_all(path.join("rl")).unwrap();
    }
}

async fn initialize_revoked_list() -> InDiskRevokedList {
    let path = path();
    InDiskRevokedList::open(path).await.unwrap()
}

fn tweak_plm_rl(plm: &InDiskPLM, rl: &InDiskRevokedList, skm: &DGSPManagerSecretKey) {
    for u in GROUP_SIZE..(GROUP_SIZE + TWEAK_USERS_SIZE) {
        let (id, cid) = FuturesExecutor
            .block_on(DGSP::join(&skm.msk, &u.to_string(), plm))
            .unwrap();
        let seed_u = DGSP::keygen_user();
        let (wots_pks, _) = DGSP::cert_sign_req_user(&seed_u, CERTIFICATE_ISSUED_SIZE);
        FuturesExecutor
            .block_on(DGSP::req_cert(
                &skm.msk,
                id,
                cid,
                &wots_pks,
                plm,
                &skm.spx_sk,
            ))
            .unwrap();

        FuturesExecutor
            .block_on(DGSP::revoke(&skm.msk, plm, vec![id], rl))
            .unwrap();
    }
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    let mut parts = vec![];

    if hours > 0 {
        parts.push(format!(
            "{} hour{}",
            hours,
            if hours > 1 { "s" } else { "" }
        ));
    }
    if minutes > 0 {
        parts.push(format!(
            "{} minute{}",
            minutes,
            if minutes > 1 { "s" } else { "" }
        ));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!(
            "{} second{}",
            seconds,
            if seconds > 1 { "s" } else { "" }
        ));
    }

    if parts.len() > 1 {
        let last = parts.pop().unwrap();
        format!("{} and {}", parts.join(", "), last)
    } else {
        parts.join("")
    }
}

fn dgsp_full_benchmarks(c: &mut Criterion) {
    let preloading_start = Instant::now();
    println!("Preloading DGSP with {GROUP_SIZE} users in progress...");
    let plm = FuturesExecutor.block_on(initialize_plm_with_users()); // This may take a while if not created previously.
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    println!(
        "Preloading database finished successfully in {}.",
        format_duration(preloading_start.elapsed())
    );

    let (pkm, mut skm) = DGSP::keygen_manager().unwrap();
    skm.msk = DGSPMSK::from(MSK);

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);

    // let plm_meta_tree = plm.open_tree("meta_tree").unwrap();
    // let plm_size_bytes = plm_meta_tree.get(b"__next_id").unwrap().unwrap();
    // let plm_size = u64::from_be_bytes(plm_size_bytes.as_ref().try_into().unwrap());
    // println!("plm_size: {plm_size}");
    // let counter = AtomicU64::new(plm_size);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();

    let mut group = c.benchmark_group(format!(
        "DGSP_full_using_{}_with_{GROUP_SIZE}_users_and_{CERTIFICATE_ISSUED_SIZE}_batch",
        detect_spx_feature()
    ));
    group.sample_size(10);

    group.bench_function("keygen_manager", |b| {
        pool.install(|| {
            b.iter(|| {
                black_box(DGSP::keygen_manager()).unwrap();
            });
        });
    });

    group.bench_function("keygen_user", |b| {
        pool.install(|| {
            b.iter(|| {
                black_box(DGSP::keygen_user());
            });
        });
    });

    group.bench_function("join", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                for _ in 0..num_iters {
                    // Precomputation
                    let username = counter.fetch_add(1, Ordering::Relaxed).to_string();

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    black_box(
                        FuturesExecutor
                            .block_on(DGSP::join(&skm.msk, &username, &plm))
                            .unwrap(),
                    );

                    // Stop timer
                    total += start.elapsed();
                }
                total
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("csr", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                for _ in 0..num_iters {
                    // Precomputation
                    let seed_u = DGSP::keygen_user();

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    black_box(DGSP::cert_sign_req_user(&seed_u, CERTIFICATE_ISSUED_SIZE));

                    // Stop timer
                    total += start.elapsed();
                }
                total
            });
        });
    });

    group.bench_function("cert", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                // 1-time Precomputation
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = FuturesExecutor
                    .block_on(DGSP::join(&skm.msk, &username, &plm))
                    .unwrap();
                let seed_u = DGSP::keygen_user();

                for _ in 0..num_iters {
                    // Precomputation
                    let (wots_pks, _) = DGSP::cert_sign_req_user(&seed_u, CERTIFICATE_ISSUED_SIZE);

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
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

                    // Stop timer
                    total += start.elapsed();
                }
                total
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("sign", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                // 1-time Precomputation
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = FuturesExecutor
                    .block_on(DGSP::join(&skm.msk, &username, &plm))
                    .unwrap();
                let seed_u = DGSP::keygen_user();
                let mut message = [0u8; 1];

                for _ in 0..num_iters {
                    // Precomputation
                    let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);
                    let mut certs = FuturesExecutor
                        .block_on(DGSP::req_cert(
                            &skm.msk,
                            id,
                            cid,
                            &wots_pks,
                            &plm,
                            &skm.spx_sk,
                        ))
                        .unwrap();
                    let wots_rand = wots_rands.pop().unwrap();
                    let cert = certs.pop().unwrap();
                    OsRng.fill_bytes(&mut message);

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    black_box(DGSP::sign(&message, wots_rand, &seed_u, cert));

                    // Stop timer
                    total += start.elapsed();
                }
                total
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("verify", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                // 1-time Precomputation
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = FuturesExecutor
                    .block_on(DGSP::join(&skm.msk, &username, &plm))
                    .unwrap();
                let seed_u = DGSP::keygen_user();
                let mut message = [0u8; 1];

                for _ in 0..num_iters {
                    // Precomputation
                    let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);
                    let mut certs = FuturesExecutor
                        .block_on(DGSP::req_cert(
                            &skm.msk,
                            id,
                            cid,
                            &wots_pks,
                            &plm,
                            &skm.spx_sk,
                        ))
                        .unwrap();
                    let wots_rand = wots_rands.pop().unwrap();
                    let cert = certs.pop().unwrap();
                    OsRng.fill_bytes(&mut message);
                    let sig = DGSP::sign(&message, wots_rand, &seed_u, cert);

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    let result = black_box(FuturesExecutor.block_on(DGSP::verify(
                        &message,
                        &sig,
                        &revoked_list,
                        &pkm,
                    )));

                    // Stop timer
                    total += start.elapsed();

                    // Check result for errors
                    result.expect("Verification failed");
                }
                total
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("open", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                // 1-time Precomputation
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = FuturesExecutor
                    .block_on(DGSP::join(&skm.msk, &username, &plm))
                    .unwrap();
                let seed_u = DGSP::keygen_user();
                let mut message = [0u8; 1];

                for _ in 0..num_iters {
                    // Precomputation
                    let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 1);
                    let mut certs = FuturesExecutor
                        .block_on(DGSP::req_cert(
                            &skm.msk,
                            id,
                            cid,
                            &wots_pks,
                            &plm,
                            &skm.spx_sk,
                        ))
                        .unwrap();
                    let wots_rand = wots_rands.pop().unwrap();
                    let cert = certs.pop().unwrap();
                    OsRng.fill_bytes(&mut message);
                    let sig = DGSP::sign(&message, wots_rand, &seed_u, cert);

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    black_box(
                        FuturesExecutor
                            .block_on(DGSP::open(&skm.msk, &plm, &sig))
                            .unwrap(),
                    );

                    // Stop timer
                    total += start.elapsed();
                }
                total
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("revoke", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                for _ in 0..num_iters {
                    // Precomputation
                    let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                    let (id, cid) = FuturesExecutor
                        .block_on(DGSP::join(&skm.msk, &username, &plm))
                        .unwrap();
                    let seed_u = DGSP::keygen_user();
                    let (wots_pks, _) = DGSP::cert_sign_req_user(&seed_u, CERTIFICATE_ISSUED_SIZE);
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

                    // Benchmark
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
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);

    group.finish();
}

criterion_group!(benches, dgsp_full_benchmarks);
criterion_main!(benches);
