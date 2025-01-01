#![allow(unused)]
use criterion::black_box;
use dgsp::dgsp::{DGSPManagerSecretKey, DGSP};
use dgsp::{InDiskPLM, InMemoryPLM, PLMInterface};
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

pub fn db_logical_size<P: AsRef<Path>>(db: &sled::Db, path: P, db_type: &str, alg: &str) -> String {
    db.flush().unwrap();
    let dir = match db_type {
        "PLM" => path.as_ref().join(alg).join("plm"),
        "RevokedList" => path.as_ref().join(alg).join("rl"),
        _ => path.as_ref().to_path_buf(),
    };

    let usage = format_size(disk_usage(dir).unwrap());
    black_box(path);
    format!(
        "Approximate logical size of {} in DGSP {}: {}",
        db_type, alg, usage
    )
}

pub fn disk_usage<P: AsRef<Path>>(path: P) -> Result<u64, dgsp::Error> {
    let entries: Vec<_> = fs::read_dir(path)?.collect::<Result<_, _>>()?;

    let sum = entries
        .par_iter()
        .map(|entry| {
            let path = entry.path();
            match fs::metadata(&path) {
                Ok(metadata) if metadata.is_dir() => disk_usage(path).unwrap_or(0),
                Ok(metadata) if metadata.is_file() => metadata.len(),
                _ => 0,
            }
        })
        .sum();

    Ok(sum)
}

pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1 << 10;
    const MB: u64 = 1 << 20;
    const GB: u64 = 1 << 30;
    const TB: u64 = 1 << 40;
    const PB: u64 = 1 << 50;
    const EB: u64 = 1 << 60;

    if bytes >= EB {
        format!("{:.2} EB", bytes as f64 / EB as f64)
    } else if bytes >= PB {
        format!("{:.2} PB", bytes as f64 / PB as f64)
    } else if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} Bytes", bytes)
    }
}
//
// #[cfg(feature = "in-memory")]
// pub struct InMemorySetup {
//     pub skm: DGSPManagerSecretKey,
//     pub plm: InMemoryPLM,
// }
//
// #[cfg(feature = "in-disk")]
// pub struct InDiskSetup {
//     pub skm: DGSPManagerSecretKey,
//     pub plm: InDiskPLM,
//     pub temp_dir: TempDir,
// }
//
// #[cfg(feature = "in-memory")]
// pub async fn setup_in_memory(group_size: u64) -> InMemorySetup {
//     let plm = InMemoryPLM::open("").await.unwrap();
//     let (_, skm) = DGSP::keygen_manager().unwrap();
//
//     // populate group with initial users
//     for u in 0..group_size {
//         DGSP::join(&skm.msk, &u.to_string(), &plm).await.unwrap();
//     }
//
//     InMemorySetup { skm, plm }
// }
//
// #[cfg(feature = "in-disk")]
// pub async fn setup_in_disk(group_size: u64, alg: &str) -> InDiskSetup {
//     let project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     let temp_dir = tempfile::Builder::new()
//         .prefix("temp_example_db_")
//         .tempdir_in(&project_root)
//         .expect("Failed to create temporary directory in project root");
//
//     let plm = InDiskPLM::open(temp_dir.path().join(alg)).await.unwrap();
//     let (_, skm) = DGSP::keygen_manager().unwrap();
//
//     // populate group with initial users
//     for u in 0..group_size {
//         DGSP::join(&skm.msk, &u.to_string(), &plm).await.unwrap();
//     }
//
//     InDiskSetup { skm, plm, temp_dir }
// }
//
// pub fn plm_show_keep(plm: &InDiskPLM, temp_dir: TempDir, alg: &str, keep: bool) {
//     let plm_usage = db_logical_size(plm, &temp_dir, "PLM", alg);
//     println!("{}", plm_usage);
//
//     // keep temp directory if requested
//     if keep {
//         let _ = temp_dir.into_path();
//     }
// }
