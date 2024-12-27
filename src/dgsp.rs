use crate::db::{PLMInterface, RevokedListInterface};
use crate::hash::DGSPHasher;
use crate::params::{DGSP_N, DGSP_POS_BYTES};
use crate::sphincs_plus::*;
use crate::utils::{array_struct, bytes_to_u64, u64_to_bytes};
use crate::wots_plus::{WotsPlus, WTS_ADRS_RAND_BYTES};
use crate::{Error, VerificationError};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use zeroize::Zeroize;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

#[cfg(feature = "in-disk")]
pub use crate::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-memory")]
pub use crate::{InMemoryPLM, InMemoryRevokedList};

/// wots_sgn_seed is pk_seed of W-OTS+
#[derive(Clone, Zeroize)]
pub struct DGSPWotsRand {
    wots_adrs_rand: [u8; WTS_ADRS_RAND_BYTES],
    wots_sgn_seed: [u8; SPX_N],
}

impl Default for DGSPWotsRand {
    fn default() -> Self {
        Self::new()
    }
}

impl DGSPWotsRand {
    pub fn new() -> Self {
        let mut wots_adrs_rand = [0u8; WTS_ADRS_RAND_BYTES];
        let mut wots_sgn_seed = [0u8; SPX_N];
        OsRng.fill_bytes(&mut wots_adrs_rand);
        OsRng.fill_bytes(&mut wots_sgn_seed);
        Self {
            wots_adrs_rand,
            wots_sgn_seed,
        }
    }
}

array_struct!(DGSPMSK, DGSP_N);

#[derive(Clone, Zeroize)]
pub struct DGSPManagerSecretKey {
    pub msk: DGSPMSK,
    pub spx_sk: SphincsPlusSecretKey,
}

#[derive(Clone, Zeroize)]
pub struct DGSPManagerPublicKey {
    pub spx_pk: SphincsPlusPublicKey,
}

#[derive(Clone, Zeroize)]
pub struct DGSPSignature {
    pub wots_sig: [u8; SPX_WOTS_BYTES],
    pub pos: [u8; DGSP_POS_BYTES],
    pub spx_sig: SphincsPlusSignature,
    pub wots_rand: DGSPWotsRand,
}

#[derive(Default)]
pub struct DGSP;

impl DGSP {
    pub fn keygen_manager() -> Result<(DGSPManagerPublicKey, DGSPManagerSecretKey), Error> {
        let sp = SphincsPlus;
        let (spx_pk, spx_sk) = sp.keygen()?;
        let mut msk = DGSPMSK::from([0u8; DGSP_N]);
        OsRng.fill_bytes(&mut msk.0);

        let sk = DGSPManagerSecretKey { msk, spx_sk };
        let pk = DGSPManagerPublicKey { spx_pk };

        Ok((pk, sk))
    }

    pub async fn join<P: PLMInterface>(
        msk: &DGSPMSK,
        username: &str,
        plm: &P,
    ) -> Result<(u64, [u8; DGSP_N]), Error> {
        let new_id = plm.add_new_user(username).await?;
        let cid = Self::calculate_cid(msk, new_id);
        Ok((new_id, cid))
    }

    pub async fn req_cert<P: PLMInterface>(
        msk: &DGSPMSK,
        id: u64,
        cid: [u8; DGSP_N],
        wotsplus_public_keys: &Vec<[u8; SPX_WOTS_PK_BYTES]>,
        plm: &P,
        sphincs_plus_secret_key: &SphincsPlusSecretKey,
    ) -> Result<Vec<([u8; DGSP_POS_BYTES], SphincsPlusSignature)>, Error> {
        Self::req_validity(msk, id, &cid, plm).await?;

        let certs: Vec<([u8; DGSP_POS_BYTES], SphincsPlusSignature)> = Self::generate_certificates(
            msk,
            id,
            wotsplus_public_keys,
            plm.get_ctr_id(id).await?,
            sphincs_plus_secret_key,
        )?;

        plm.increment_ctr_id_by(id, wotsplus_public_keys.len() as u64)
            .await?;

        Ok(certs)
    }

    pub fn generate_certificates(
        msk: &DGSPMSK,
        id: u64,
        wotsplus_public_keys: &Vec<[u8; SPX_WOTS_PK_BYTES]>,
        ctr_id: u64,
        sphincs_plus_sk: &SphincsPlusSecretKey,
    ) -> Result<Vec<([u8; DGSP_POS_BYTES], SphincsPlusSignature)>, Error> {
        // Initialize AES-256 cipher
        let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));

        wotsplus_public_keys
            .par_iter()
            .enumerate()
            .map(|(i, wots_pk)| {
                let mut pos = [0u8; DGSP_POS_BYTES];

                // Combine id and ctr + i into the input block
                pos[..8].copy_from_slice(&u64_to_bytes(id));
                pos[8..].copy_from_slice(&u64_to_bytes(ctr_id + (i as u64)));

                // Encrypt the DGSP.pos
                let block_generic = GenericArray::from_mut_slice(&mut pos);
                cipher.encrypt_block(block_generic);

                let mut message = [0u8; SPX_WOTS_PK_BYTES + 16];

                // Combine wots_pk and dgsp.pos into the input message block
                message[..SPX_WOTS_PK_BYTES].copy_from_slice(wots_pk);
                message[SPX_WOTS_PK_BYTES..].copy_from_slice(&pos);

                Ok::<([u8; 16], SphincsPlusSignature), Error>((
                    pos,
                    SphincsPlus.sign(&message, sphincs_plus_sk)?,
                ))
            })
            .collect::<Result<Vec<([u8; DGSP_POS_BYTES], SphincsPlusSignature)>, Error>>()
    }

    pub async fn revoke<P: PLMInterface, R: RevokedListInterface>(
        msk: &DGSPMSK,
        plm: &P,
        to_be_revoked: Vec<u64>,
        revoked_list: &R,
    ) -> Result<(), Error> {
        for r in to_be_revoked {
            if plm.id_exists(r).await? && plm.id_is_active(r).await? {
                let pos_list = Self::par_dgsp_pos(msk, r, 0, plm.get_ctr_id(r).await?);
                for pos in pos_list {
                    revoked_list.insert(pos).await?;
                }
                plm.deactivate_id(r).await?;
            }
        }
        Ok(())
    }

    pub async fn open<P: PLMInterface>(
        msk: &DGSPMSK,
        plm: &P,
        sig: &DGSPSignature,
    ) -> Result<(u64, String), Error> {
        let mut pos = sig.pos;
        let block = GenericArray::from_mut_slice(&mut pos);

        // Initialize cipher
        let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));
        // Decrypt the block
        cipher.decrypt_block(block);

        let id = bytes_to_u64(&pos[..8]);
        Ok((id, plm.get_username(id).await?))
    }

    fn calculate_cid(msk: &DGSPMSK, id: u64) -> [u8; DGSP_N] {
        let mut cid = [0u8; DGSP_N];
        DGSPHasher::calc_cid(cid.as_mut(), msk.as_ref(), &u64_to_bytes(id));
        cid
    }

    async fn req_validity<P: PLMInterface>(
        msk: &DGSPMSK,
        id: u64,
        cid: &[u8; DGSP_N],
        plm: &P,
    ) -> Result<(), Error> {
        // check if user exists and is active
        if !plm.id_exists(id).await? || !plm.id_is_active(id).await? {
            return Err(Error::InvalidCertReq);
        }

        // check if user cid is correct
        if *cid != Self::calculate_cid(msk, id) {
            return Err(Error::InvalidCertReq);
        }
        Ok(())
    }

    fn par_dgsp_pos(msk: &DGSPMSK, id: u64, ctr_id: u64, b: u64) -> Vec<[u8; DGSP_POS_BYTES]> {
        // Perform parallel encryption
        (0..b)
            .into_par_iter()
            .map(|i| {
                let mut block = [0u8; DGSP_POS_BYTES];

                // Combine pk and ctr + i into the input block
                block[..8].copy_from_slice(&u64_to_bytes(id));
                block[8..].copy_from_slice(&u64_to_bytes(ctr_id + i));

                // Initialize AES-256 cipher
                let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));

                // Encrypt the block
                let block_generic = GenericArray::from_mut_slice(&mut block);
                cipher.encrypt_block(block_generic);

                block
            })
            .collect()
    }

    pub fn keygen_user() -> [u8; SPX_N] {
        let mut seed_user: [u8; SPX_N] = [0; SPX_N];
        OsRng.fill_bytes(&mut seed_user);
        seed_user
    }

    pub fn cert_sign_req_user(
        seed_user: &[u8; SPX_N],
        b: usize,
    ) -> (Vec<[u8; SPX_WOTS_PK_BYTES]>, Vec<DGSPWotsRand>) {
        (0..b)
            .into_par_iter()
            .map(|_| {
                let wots_rand = DGSPWotsRand::new();
                let wp =
                    WotsPlus::new_from_rand(&wots_rand.wots_adrs_rand, &wots_rand.wots_sgn_seed);
                let (pk_wots, _) = wp.keygen(seed_user);
                (pk_wots, wots_rand)
            })
            .unzip()
    }

    /// hm = H(R || SGN.seed || pos || Message)
    ///
    ///   n *     n     *  16  *   m
    pub fn sign(
        message: &[u8],
        wots_rand: &DGSPWotsRand,
        seed_user: &[u8; SPX_N],
        cert: ([u8; DGSP_POS_BYTES], SphincsPlusSignature),
    ) -> DGSPSignature {
        let mut hm = [0u8; SPX_N];
        DGSPHasher::hash_m(
            &mut hm,
            cert.1.as_ref(),
            &wots_rand.wots_sgn_seed,
            &cert.0,
            message,
        );

        let wp = WotsPlus::new_from_rand(&wots_rand.wots_adrs_rand, &wots_rand.wots_sgn_seed);
        let wots_sig = wp.sign_from_sk_seed(&hm, seed_user);

        DGSPSignature {
            wots_sig,
            pos: cert.0,
            spx_sig: cert.1,
            wots_rand: wots_rand.clone(),
        }
    }

    pub async fn verify<R: RevokedListInterface>(
        message: &[u8],
        sig: &DGSPSignature,
        revoked_list: &R,
        pk: &DGSPManagerPublicKey,
    ) -> Result<(), Error> {
        if revoked_list.contains(&sig.pos).await? {
            return Err(VerificationError::RevokedSignature)?;
        }

        let mut hm = [0u8; SPX_N];
        DGSPHasher::hash_m(
            &mut hm,
            sig.spx_sig.as_ref(),
            &sig.wots_rand.wots_sgn_seed,
            &sig.pos,
            message,
        );

        let wp =
            WotsPlus::new_from_rand(&sig.wots_rand.wots_adrs_rand, &sig.wots_rand.wots_sgn_seed);
        let wots_pk = wp.pk_from_sig(&sig.wots_sig, &hm);

        let mut spx_msg = [0u8; SPX_WOTS_PK_BYTES + DGSP_POS_BYTES];
        spx_msg[..SPX_WOTS_PK_BYTES].copy_from_slice(wots_pk.as_ref());
        spx_msg[SPX_WOTS_PK_BYTES..].copy_from_slice(sig.pos.as_ref());

        SphincsPlus.verify(&sig.spx_sig, &spx_msg, &pk.spx_pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::path::PathBuf;
    use tempfile::Builder;

    #[cfg(feature = "in-disk")]
    use crate::db::in_disk::{InDiskPLM, InDiskRevokedList};
    #[cfg(feature = "in-memory")]
    use crate::db::in_memory::{InMemoryPLM, InMemoryRevokedList};

    fn random_str(length: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    #[tokio::test]
    #[cfg(feature = "in-disk")]
    async fn test_dgsp_in_disk() {
        // Create a temporary directory for test in the project root
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let temp_dir = Builder::new()
            .prefix("temp_example_db_")
            .tempdir_in(&project_root)
            .expect("Failed to create temporary directory in project root");

        // Create PL_M
        let plm = InDiskPLM::open(temp_dir.path().join("dgsp")).await.unwrap();

        // Create Revoked List:
        let revoked_list = InDiskRevokedList::open(temp_dir.path().join("dgsp"))
            .await
            .unwrap();

        // Create manager keys
        let (pk_m, sk_m) = DGSP::keygen_manager().unwrap();

        // Create user u1 and join
        let seed_u1 = DGSP::keygen_user();
        let username_u1 = random_str(10);
        // let username_u1 = "0";
        let (id_u1, cid_u1) = DGSP::join(&sk_m.msk, username_u1.as_str(), &plm)
            .await
            .unwrap();

        // Create a batch of CSR
        const B: usize = 3;
        let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u1, B);

        // Obtain certificates for the given csr batch
        let mut certs = DGSP::req_cert(&sk_m.msk, id_u1, cid_u1, &wots_pks, &plm, &sk_m.spx_sk)
            .await
            .unwrap();

        // Sign a single message
        let mut rng = thread_rng();
        let len: u8 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let wots_rand = wots_rands.pop().unwrap();
        let cert = certs.pop().unwrap();
        let sig = DGSP::sign(&message, &wots_rand, &seed_u1, cert);

        // Verify the signature
        DGSP::verify(&message, &sig, &revoked_list, &pk_m)
            .await
            .unwrap();

        // Obtain username and id from sig
        assert_eq!(
            DGSP::open(&sk_m.msk, &plm, &sig).await.unwrap(),
            (id_u1, username_u1)
        );

        // Revoke a user and its certificates
        DGSP::revoke(&sk_m.msk, &plm, vec![id_u1], &revoked_list)
            .await
            .unwrap();
        assert!(revoked_list.contains(&sig.pos).await.unwrap());

        for cert in &certs {
            assert!(revoked_list.contains(&cert.0).await.unwrap());
        }

        // Make sure no cert will be created for that id from now on.
        let (wots_pks_new, _) = DGSP::cert_sign_req_user(&seed_u1, 1);
        assert_eq!(
            DGSP::req_cert(&sk_m.msk, id_u1, cid_u1, &wots_pks_new, &plm, &sk_m.spx_sk).await,
            Err(Error::InvalidCertReq)
        );

        // Make sure no signatures created by the revoked user will verify
        let wots_rand_new = wots_rands.pop().unwrap();
        let cert_new = certs.pop().unwrap();
        let message_new = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
        let sig_new = DGSP::sign(&message_new, &wots_rand_new, &seed_u1, cert_new);
        assert_eq!(
            DGSP::verify(&message_new, &sig_new, &revoked_list, &pk_m).await,
            Err(Error::VerificationFailed(
                VerificationError::RevokedSignature
            ))
        );
    }

    #[tokio::test]
    #[cfg(feature = "in-memory")]
    async fn test_dgsp_in_memory() {
        // Create a temporary directory for test in the project root
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let temp_dir = Builder::new()
            .prefix("temp_example_db_")
            .tempdir_in(&project_root)
            .expect("Failed to create temporary directory in project root");

        // Create PL_M
        let plm = InMemoryPLM::open(temp_dir.path().join("dgsp"))
            .await
            .unwrap();

        // Create manager keys
        let revoked_list = InMemoryRevokedList::open(temp_dir.path().join("dgsp"))
            .await
            .unwrap();

        // Create manager keys
        let (pk_m, sk_m) = DGSP::keygen_manager().unwrap();

        // Create user u1 and join
        let seed_u1 = DGSP::keygen_user();
        let username_u1 = random_str(10);
        // let username_u1 = "0";
        let (id_u1, cid_u1) = DGSP::join(&sk_m.msk, username_u1.as_str(), &plm)
            .await
            .unwrap();

        // Create a batch of CSR
        const B: usize = 3;
        let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u1, B);

        // Obtain certificates for the given csr batch
        let mut certs = DGSP::req_cert(&sk_m.msk, id_u1, cid_u1, &wots_pks, &plm, &sk_m.spx_sk)
            .await
            .unwrap();

        // Sign a single message
        let mut rng = thread_rng();
        let len: u8 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let wots_rand = wots_rands.pop().unwrap();
        let cert = certs.pop().unwrap();
        let sig = DGSP::sign(&message, &wots_rand, &seed_u1, cert);

        // Verify the signature
        DGSP::verify(&message, &sig, &revoked_list, &pk_m)
            .await
            .unwrap();

        // Obtain username and id from sig
        assert_eq!(
            DGSP::open(&sk_m.msk, &plm, &sig).await.unwrap(),
            (id_u1, username_u1)
        );

        // Revoke a user and its certificates
        DGSP::revoke(&sk_m.msk, &plm, vec![id_u1], &revoked_list)
            .await
            .unwrap();
        assert!(revoked_list.contains(&sig.pos).await.unwrap());

        for cert in &certs {
            assert!(revoked_list.contains(&cert.0).await.unwrap());
        }

        // Make sure no cert will be created for that id from now on.
        let (wots_pks_new, _) = DGSP::cert_sign_req_user(&seed_u1, 1);
        assert_eq!(
            DGSP::req_cert(&sk_m.msk, id_u1, cid_u1, &wots_pks_new, &plm, &sk_m.spx_sk).await,
            Err(Error::InvalidCertReq)
        );

        // Make sure no signatures created by the revoked user will verify
        let wots_rand_new = wots_rands.pop().unwrap();
        let cert_new = certs.pop().unwrap();
        let message_new = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
        let sig_new = DGSP::sign(&message_new, &wots_rand_new, &seed_u1, cert_new);
        assert_eq!(
            DGSP::verify(&message_new, &sig_new, &revoked_list, &pk_m).await,
            Err(Error::VerificationFailed(
                VerificationError::RevokedSignature
            ))
        );
    }
}
