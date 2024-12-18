#[cfg(feature = "in-disk")]
pub mod in_disk;
#[cfg(feature = "in-memory")]
pub mod in_memory;

#[cfg(test)]
mod tests {
    #[cfg(feature = "in-disk")]
    use crate::db::in_disk::*;
    #[cfg(feature = "in-memory")]
    use crate::db::in_memory::*;

    use crate::error::Error;
    use crate::params::DGSP_POS_BYTES;
    use rand::distributions::Alphanumeric;
    use rand::rngs::OsRng;
    use rand::{Rng, RngCore};
    use tempfile::TempDir;

    const TEST_DB_PATH: &str = "test_db";

    fn random_str(length: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    #[test]
    fn test_plm_add_username() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = PLM::open_with_path(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let id = plm.add_new_user(&username).unwrap();
        assert_eq!(id, 0u64);
        assert_eq!(
            plm.add_new_user(&username),
            Err(Error::UsernameAlreadyExists(username.clone()))
        );
        let id2 = plm.add_new_user(format!("{}2", username).as_str()).unwrap();
        assert_eq!(id2, 1u64);
    }

    #[test]
    fn test_plm_id() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = PLM::open_with_path(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let id = plm.add_new_user(&username).unwrap();
        assert!(plm.id_exists(id).unwrap());
        assert!(plm.id_is_active(id).unwrap());
        assert_eq!(plm.get_ctr_id(id).unwrap(), 0u64);
        assert_eq!(plm.get_username(id).unwrap(), username);
        plm.deactivate_id(id).unwrap();
        assert!(!plm.id_is_active(id).unwrap());
    }

    #[test]
    fn test_plm_ctr_cert() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = PLM::open_with_path(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let id = plm.add_new_user(&username).unwrap();
        plm.increment_ctr_id_by(id, 1u64).unwrap();
        assert_eq!(plm.get_ctr_id(id).unwrap(), 1u64);

        #[cfg(feature = "in-disk")]
        let error_prefix = "sled error: Unsupported: ";
        #[cfg(feature = "in-memory")]
        let error_prefix = "";

        assert_eq!(
            plm.increment_ctr_id_by(id, u64::MAX),
            Err(Error::DbInternalError(format!(
                "{}Exceeds max certificate generation for the user {}",
                error_prefix, id
            )))
        );
    }

    #[test]
    fn test_revoked_list() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let rl = RevokedList::open_with_path(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let mut pos = [0u8; DGSP_POS_BYTES];
        OsRng.fill_bytes(&mut pos);
        assert!(!rl.contains(&pos).unwrap());
        rl.insert(pos).unwrap();
        assert!(rl.contains(&pos).unwrap());
    }
}
