#![cfg(all(feature = "in-memory", feature = "benchmarking"))]

use crate::bench_utils::*;
use criterion::async_executor::{AsyncExecutor, FuturesExecutor};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP, DGSPMSK};
use dgsp::params::DGSP_N;
use dgsp::{InMemoryPLM, InMemoryRevokedList, PLMInterface, RevokedListInterface};
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::ThreadPoolBuilder;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

mod bench_utils;

const MSK: [u8; DGSP_N] = [170_u8; DGSP_N];
const GROUP_SIZE: u64 = 1 << 10;
const CERTIFICATE_ISSUED_SIZE: usize = 1 << 0; // batch size
const TWEAK_USERS_SIZE: u64 = 10;

async fn initialize_plm_with_users() -> InMemoryPLM {
    let plm = InMemoryPLM::open("").await.unwrap();

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

    plm
}

fn reset_plm(plm: &InMemoryPLM) {
    plm.delete_sequential_usernames_to_the_end(GROUP_SIZE)
        .unwrap()
}

fn delete_revoked_list(_revoked_list: InMemoryRevokedList) {}

async fn initialize_revoked_list() -> InMemoryRevokedList {
    InMemoryRevokedList::open("").await.unwrap()
}

fn tweak_plm_rl(plm: &InMemoryPLM, rl: &InMemoryRevokedList, skm: &DGSPManagerSecretKey) {
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

    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();

    let mut group = c.benchmark_group(format!(
        "DGSP_in_memory_using_{}_with_{GROUP_SIZE}_users_and_{CERTIFICATE_ISSUED_SIZE}_batch",
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

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);

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

    println!("Resetting database...");
    reset_plm(&plm);
    delete_revoked_list(revoked_list);
    let revoked_list = FuturesExecutor.block_on(initialize_revoked_list());
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

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

    group.finish();
}

criterion_group!(benches, dgsp_full_benchmarks);
criterion_main!(benches);
