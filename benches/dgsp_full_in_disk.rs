#![cfg(all(feature = "in-disk", feature = "benchmarking"))]

use crate::bench_utils::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP, DGSPMSK};
use dgsp::params::DGSP_N;
use dgsp::{InDiskPLM, InDiskRevokedList, PLMInterface, RevokedListInterface};
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::ThreadPoolBuilder;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

mod bench_utils;

const MSK: [u8; DGSP_N] = [170_u8; DGSP_N];
const GROUP_SIZE: u64 = 1 << 25;
const CERTIFICATE_ISSUED_SIZE: usize = 1;
const TWEAK_USERS_SIZE: u64 = 10;

fn path() -> PathBuf {
    PathBuf::from(format!(
        "dgsp_{}_with_{}_users",
        detect_spx_feature(),
        GROUP_SIZE
    ))
}

// fn initialize_plm_with_users() -> InDiskPLM {
//     let path = path();
//     let db_preloaded = path.join("plm").exists();
//
//     let plm = InDiskPLM::open(path).unwrap();
//
//     if !db_preloaded {
//         (0..GROUP_SIZE).for_each(|u| {
//             DGSP::join(&DGSPMSK::from(MSK), &u.to_string(), &plm).unwrap();
//         });
//     }
//     plm.flush_plm().unwrap();
//
//     plm
// }

fn initialize_plm_with_users() -> InDiskPLM {
    let path = path();
    let db_preloaded = path.join("plm").exists();
    let plm = InDiskPLM::open(path).unwrap();

    if !db_preloaded {
        // Instead of inserting all users at once, do it in batches.
        let chunk_size = 10_000;
        let mut start = 0;
        while start < GROUP_SIZE {
            let end = std::cmp::min(start + chunk_size, GROUP_SIZE);
            for u in start..end {
                DGSP::join(&DGSPMSK::from(MSK), &u.to_string(), &plm)
                    .expect("Join should not fail");
            }
            // Flush the database after each chunk.
            plm.flush_plm().unwrap();
            start = end;
        }
    }
    plm.flush_plm().unwrap();
    plm
}

fn reset_plm(plm: &InDiskPLM) {
    plm.delete_sequential_usernames_to_the_end(GROUP_SIZE)
        .unwrap();
}

fn clear_revoked_list(revoked_list: &InDiskRevokedList) {
    revoked_list.clear().unwrap();
}

fn initialize_revoked_list() -> InDiskRevokedList {
    InDiskRevokedList::open(path()).unwrap()
}

fn tweak_plm_rl(plm: &InDiskPLM, rl: &InDiskRevokedList, skm: &DGSPManagerSecretKey) {
    for u in GROUP_SIZE..(GROUP_SIZE + TWEAK_USERS_SIZE) {
        let (id, cid) = DGSP::join(&skm.msk, &u.to_string(), plm).unwrap();
        let seed_u = DGSP::keygen_user();
        let (wots_pks, _) = DGSP::csr(&seed_u, CERTIFICATE_ISSUED_SIZE);
        DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, plm, &skm.spx_sk).unwrap();
        DGSP::revoke(&skm.msk, plm, &[id], rl).unwrap();
    }
}

fn dgsp_full_benchmarks(c: &mut Criterion) {
    let preloading_start = Instant::now();
    println!("Preloading DGSP with {GROUP_SIZE} users in progress...");
    let plm = initialize_plm_with_users(); // This may take a while if not created previously.
    let revoked_list = initialize_revoked_list();
    println!(
        "Preloading database finished successfully in {}.",
        format_duration(preloading_start.elapsed())
    );

    let (pkm, mut skm) = DGSP::keygen_manager().unwrap();
    skm.msk = DGSPMSK::from(MSK);

    let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();

    let mut group = c.benchmark_group(format!(
        "DGSP_in_disk_using_{}_with_{GROUP_SIZE}_users_and_{CERTIFICATE_ISSUED_SIZE}_batch",
        detect_spx_feature()
    ));
    group.sample_size(100);

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
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);

    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("join", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                for _ in 0..num_iters {
                    // Precomputation
                    let iter = counter.fetch_add(1, Ordering::Relaxed);
                    let username = iter.to_string();

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    black_box(DGSP::join(&skm.msk, &username, &plm).unwrap());

                    // Stop timer
                    total += start.elapsed();

                    // Make sure sled Db is following the load of joining users every once in a while
                    // If the database reset did not halt, flush the plm in a shorter period.
                    if iter % 1000 == 0 {
                        plm.flush_plm().unwrap();
                    }
                }
                total
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);

    group.bench_function("csr", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let seed_u = DGSP::keygen_user();

                let start = Instant::now();
                for _ in 0..num_iters {
                    black_box(DGSP::csr(&seed_u, black_box(CERTIFICATE_ISSUED_SIZE)));
                }
                start.elapsed()
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);

    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("gen_cert", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = DGSP::join(&skm.msk, &username, &plm).unwrap();
                let seed_u = DGSP::keygen_user();
                let (wots_pks, _) = DGSP::csr(&seed_u, CERTIFICATE_ISSUED_SIZE);

                let start = Instant::now();
                for _ in 0..num_iters {
                    black_box(
                        DGSP::gen_cert(&skm.msk, id, &cid, black_box(&wots_pks), &plm, &skm.spx_sk)
                            .unwrap(),
                    );
                }
                start.elapsed()
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("check_cert", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = DGSP::join(&skm.msk, &username, &plm).unwrap();
                let seed_u = DGSP::keygen_user();
                let mut message = [0u8; 1];
                let (wots_pks, _) = DGSP::csr(&seed_u, CERTIFICATE_ISSUED_SIZE);
                let certs =
                    DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
                OsRng.fill_bytes(&mut message);

                let start = Instant::now();
                for _ in 0..num_iters {
                    let result = black_box(DGSP::check_cert(
                        id,
                        &cid,
                        &wots_pks,
                        black_box(&certs),
                        &pkm,
                    ));
                    result.expect("Check certificates failed");
                }
                start.elapsed()
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("sign", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = DGSP::join(&skm.msk, &username, &plm).unwrap();
                let seed_u = DGSP::keygen_user();
                let mut message = [0u8; 1];
                let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, 1);
                let mut certs =
                    DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
                let wots_rand = wots_rands.pop().unwrap();
                let cert = certs.pop().unwrap();
                OsRng.fill_bytes(&mut message);

                let start = Instant::now();
                for _ in 0..num_iters {
                    black_box(DGSP::sign(
                        black_box(&message),
                        &seed_u,
                        id,
                        &cid,
                        wots_rand.clone(),
                        cert.clone(),
                    ));
                }
                start.elapsed()
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("verify", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = DGSP::join(&skm.msk, &username, &plm).unwrap();
                let seed_u = DGSP::keygen_user();
                let mut message = [0u8; 1];
                let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, 1);
                let mut certs =
                    DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
                let wots_rand = wots_rands.pop().unwrap();
                let cert = certs.pop().unwrap();
                OsRng.fill_bytes(&mut message);
                let sig = DGSP::sign(&message, &seed_u, id, &cid, wots_rand, cert);

                let start = Instant::now();
                for _ in 0..num_iters {
                    let result =
                        black_box(DGSP::verify(black_box(&message), &sig, &revoked_list, &pkm));
                    result.expect("Verification failed");
                }
                start.elapsed()
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("open", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = DGSP::join(&skm.msk, &username, &plm).unwrap();
                let seed_u = DGSP::keygen_user();
                let mut message = [0u8; 1];
                let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, 1);
                let mut certs =
                    DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
                let wots_rand = wots_rands.pop().unwrap();
                let cert = certs.pop().unwrap();
                OsRng.fill_bytes(&mut message);
                let sig = DGSP::sign(&message, &seed_u, id, &cid, wots_rand, cert);

                let start = Instant::now();
                for _ in 0..num_iters {
                    black_box(DGSP::open(&skm.msk, &plm, &sig, black_box(&message)).unwrap());
                }
                start.elapsed()
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("judge", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                let (id, cid) = DGSP::join(&skm.msk, &username, &plm).unwrap();
                let seed_u = DGSP::keygen_user();
                let mut message = [0u8; 1];
                let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, 1);
                let mut certs =
                    DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
                let wots_rand = wots_rands.pop().unwrap();
                let cert = certs.pop().unwrap();
                OsRng.fill_bytes(&mut message);
                let sig = DGSP::sign(&message, &seed_u, id, &cid, wots_rand, cert);
                let (id_opened, _, proof) =
                    DGSP::open(&skm.msk, &plm, &sig, black_box(&message)).unwrap();

                let start = Instant::now();
                for _ in 0..num_iters {
                    let result =
                        black_box(DGSP::judge(&sig, black_box(&message), id_opened, &proof));
                    result.expect("Judge failed");
                }
                start.elapsed()
            });
        });
    });

    println!("Resetting database...");
    reset_plm(&plm);
    clear_revoked_list(&revoked_list);
    tweak_plm_rl(&plm, &revoked_list, &skm);
    let counter = AtomicU64::new(GROUP_SIZE + TWEAK_USERS_SIZE);

    group.bench_function("revoke", |b| {
        pool.install(|| {
            b.iter_custom(|num_iters| {
                let mut total = Duration::ZERO;

                for _ in 0..num_iters {
                    // Precomputation
                    let username = counter.fetch_add(1, Ordering::Relaxed).to_string();
                    let (id, cid) = DGSP::join(&skm.msk, &username, &plm).unwrap();
                    let seed_u = DGSP::keygen_user();
                    let (wots_pks, _) = DGSP::csr(&seed_u, CERTIFICATE_ISSUED_SIZE);
                    black_box(
                        DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap(),
                    );

                    // Start timer
                    let start = Instant::now();

                    // Benchmark
                    let result = black_box(DGSP::revoke(&skm.msk, &plm, &[id], &revoked_list));

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

    group.finish();
    println!("Benchmarking in-disk for Group-size:{GROUP_SIZE} and Batch-size:{CERTIFICATE_ISSUED_SIZE} finished successfully.");
}

criterion_group!(benches, dgsp_full_benchmarks);
criterion_main!(benches);
