//! # DGSP...

use crate::cipher::DGSPCipher;
use crate::db::{PLMInterface, RevokedListInterface};
use crate::hash::DGSPHasher;
use crate::params::{DGSP_N, DGSP_NU_BYTES, DGSP_USER_BYTES};
use crate::sphincs_plus::*;
use crate::utils::{array_struct, bytes_to_u64, u64_to_bytes};
use crate::wots_plus::{WotsPlus, WTS_ADRS_RAND_BYTES};
use crate::{Error, Result, VerificationError};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use zeroize::Zeroize;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

/// wots_sgn_seed is pk_seed of W-OTS+
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPWotsRand {
    wots_sgn_seed: [u8; DGSP_N],
    wots_adrs_rand: [u8; WTS_ADRS_RAND_BYTES],
}

impl Default for DGSPWotsRand {
    fn default() -> Self {
        Self::new()
    }
}

impl DGSPWotsRand {
    pub fn new() -> Self {
        let mut wots_adrs_rand = [0u8; WTS_ADRS_RAND_BYTES];
        let mut wots_sgn_seed = [0u8; DGSP_N];
        OsRng.fill_bytes(&mut wots_adrs_rand);
        OsRng.fill_bytes(&mut wots_sgn_seed);
        Self {
            wots_adrs_rand,
            wots_sgn_seed,
        }
    }
}

array_struct!(DGSPMSK, DGSP_N);

#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPManagerSecretKey {
    pub msk: DGSPMSK,
    pub spx_sk: SphincsPlusSecretKey,
}

#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPManagerPublicKey {
    pub spx_pk: SphincsPlusPublicKey,
}

#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPSignature {
    #[cfg_attr(feature = "serialization", serde(with = "BigArray"))]
    pub wots_sig: [u8; SPX_WOTS_BYTES],
    pub nu: [u8; DGSP_NU_BYTES],
    pub spx_sig: SphincsPlusSignature,
    pub wots_rand: DGSPWotsRand,
    pub tau: [u8; DGSP_N],
}

#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPCert {
    pub nu: [u8; DGSP_NU_BYTES],
    pub spx_sig: SphincsPlusSignature,
}

#[derive(Default)]
pub struct DGSP;

impl DGSP {
    pub fn keygen_manager() -> Result<(DGSPManagerPublicKey, DGSPManagerSecretKey)> {
        let (spx_pk, spx_sk) = SphincsPlus::keygen()?;
        let mut msk = DGSPMSK::from([0u8; DGSP_N]);
        OsRng.fill_bytes(&mut msk.0);

        let sk = DGSPManagerSecretKey { msk, spx_sk };
        let pk = DGSPManagerPublicKey { spx_pk };

        Ok((pk, sk))
    }

    pub fn join<P: PLMInterface>(
        msk: &DGSPMSK,
        username: &str,
        plm: &P,
    ) -> Result<(u64, [u8; DGSP_N])> {
        let id = plm.add_new_user(username)?;
        let cid = Self::calculate_cid(msk, id);
        Ok((id, cid))
    }

    pub fn gen_cert<P: PLMInterface>(
        msk: &DGSPMSK,
        id: u64,
        cid: &[u8; DGSP_N],
        wotsplus_public_keys: &[[u8; DGSP_N]],
        plm: &P,
        sphincs_plus_secret_key: &SphincsPlusSecretKey,
    ) -> Result<Vec<DGSPCert>> {
        Self::req_validity(msk, id, cid, plm)?;

        let certs = Self::par_calculate_certificates(
            msk,
            id,
            cid,
            wotsplus_public_keys,
            plm.get_ctr_id(id)?,
            sphincs_plus_secret_key,
        )?;

        plm.increment_ctr_id_by(id, wotsplus_public_keys.len() as u64)?;

        Ok(certs)
    }

    fn par_calculate_certificates(
        msk: &DGSPMSK,
        id: u64,
        cid: &[u8; DGSP_N],
        wotsplus_public_keys: &[[u8; DGSP_N]],
        ctr_id: u64,
        sphincs_plus_sk: &SphincsPlusSecretKey,
    ) -> Result<Vec<DGSPCert>> {
        // Initialize cipher
        let cipher = DGSPCipher::cipher(msk);

        wotsplus_public_keys
            .par_iter()
            .enumerate()
            .map(|(i, wots_pk)| {
                let mut nu = [0u8; DGSP_NU_BYTES];

                // Combine id and ctr + i into the input block
                nu[..DGSP_USER_BYTES].copy_from_slice(&u64_to_bytes(id));
                nu[DGSP_USER_BYTES..].copy_from_slice(&u64_to_bytes(ctr_id + (i as u64)));

                // Encrypt the nu
                let block_generic = GenericArray::from_mut_slice(&mut nu);
                cipher.encrypt_block(block_generic);

                // Calculate pi and tau
                let pi = Self::calculate_pi(wots_pk, cid);
                let tau = Self::calculate_tau(wots_pk, &pi, id);

                let spx_msg = Self::prepare_spx_msg(wots_pk, &nu, &tau);
                let spx_sig = SphincsPlus::sign(&spx_msg, sphincs_plus_sk)?;

                let cert = DGSPCert { nu, spx_sig };

                Ok(cert)
            })
            .collect::<Result<Vec<DGSPCert>>>()
    }

    pub fn revoke<P: PLMInterface, R: RevokedListInterface>(
        msk: &DGSPMSK,
        plm: &P,
        to_be_revoked: &[u64],
        revoked_list: &R,
    ) -> Result<()> {
        for &r in to_be_revoked {
            if plm.id_exists(r)? && plm.id_is_active(r)? {
                let nu_list = Self::par_calculate_nu(msk, r, 0, plm.get_ctr_id(r)?);
                for nu in nu_list {
                    revoked_list.insert(nu)?;
                }
                plm.deactivate_id(r)?;
            }
        }
        Ok(())
    }

    pub fn open<P: PLMInterface>(
        msk: &DGSPMSK,
        plm: &P,
        sig: &DGSPSignature,
        message: &[u8],
    ) -> Result<(u64, String, [u8; DGSP_N])> {
        let mut nu = sig.nu;
        let block = GenericArray::from_mut_slice(&mut nu);

        let cipher = DGSPCipher::cipher(msk);
        cipher.decrypt_block(block);

        let id = bytes_to_u64(&nu[..8]);
        plm.id_exists(id)?;

        let wp =
            WotsPlus::new_from_rand(&sig.wots_rand.wots_adrs_rand, &sig.wots_rand.wots_sgn_seed);
        let wots_pk = wp.pk_from_sig(&sig.wots_sig, message);

        // calculate pi from wots_pk and msk
        let cid = Self::calculate_cid(msk, id);
        let pi = Self::calculate_pi(&wots_pk, &cid);

        Ok((id, plm.get_username(id)?, pi))
    }

    fn hash_simple(input: &[u8]) -> [u8; DGSP_N] {
        let mut output = [0u8; DGSP_N];
        DGSPHasher::hash_simple(&mut output, input);
        output
    }

    fn calculate_pi(pk: &[u8], cid: &[u8]) -> [u8; DGSP_N] {
        let mut input = [0u8; 2 * DGSP_N];
        input[..DGSP_N].copy_from_slice(pk[..DGSP_N].as_ref());
        input[DGSP_N..].copy_from_slice(cid[..DGSP_N].as_ref());
        Self::hash_simple(&input)
    }

    fn calculate_tau(pk: &[u8], pi: &[u8], id: u64) -> [u8; DGSP_N] {
        let mut input = [0u8; 2 * DGSP_N + DGSP_USER_BYTES];
        input[..DGSP_N].copy_from_slice(pk[..DGSP_N].as_ref());
        input[DGSP_N..2 * DGSP_N].copy_from_slice(pi[..DGSP_N].as_ref());
        input[2 * DGSP_N..].copy_from_slice(u64_to_bytes(id).as_ref());
        Self::hash_simple(&input)
    }

    fn calculate_cid(msk: &DGSPMSK, id: u64) -> [u8; DGSP_N] {
        let mut cid = [0u8; DGSP_N];
        DGSPHasher::calc_cid(cid.as_mut(), msk.as_ref(), &u64_to_bytes(id));
        cid
    }

    /// The SPHINCS+ message pattern is: (wots_pk || nu || tau)
    fn prepare_spx_msg(
        wots_pk: &[u8; DGSP_N],
        nu: &[u8; DGSP_NU_BYTES],
        tau: &[u8; DGSP_N],
    ) -> [u8; DGSP_N + DGSP_NU_BYTES + DGSP_N] {
        let mut spx_msg = [0u8; DGSP_N + DGSP_NU_BYTES + DGSP_N];
        spx_msg[..DGSP_N].copy_from_slice(wots_pk);
        spx_msg[DGSP_N..DGSP_N + DGSP_NU_BYTES].copy_from_slice(nu);
        spx_msg[DGSP_N + DGSP_NU_BYTES..].copy_from_slice(tau);
        spx_msg
    }

    fn req_validity<P: PLMInterface>(
        msk: &DGSPMSK,
        id: u64,
        cid: &[u8; DGSP_N],
        plm: &P,
    ) -> Result<()> {
        // check if user exists and is active
        if !plm.id_exists(id)? || !plm.id_is_active(id)? {
            return Err(Error::InvalidCertReq);
        }

        // check if user cid is correct
        if *cid != Self::calculate_cid(msk, id) {
            return Err(Error::InvalidCertReq);
        }
        Ok(())
    }

    fn par_calculate_nu(msk: &DGSPMSK, id: u64, ctr_id: u64, b: u64) -> Vec<[u8; DGSP_NU_BYTES]> {
        let cipher = DGSPCipher::cipher(msk);

        // Perform parallel encryption
        (0..b)
            .into_par_iter()
            .map(|i| {
                let mut block = [0u8; DGSP_NU_BYTES];

                // Combine pk and ctr + i into the input block
                block[..8].copy_from_slice(&u64_to_bytes(id));
                block[8..].copy_from_slice(&u64_to_bytes(ctr_id + i));

                // Encrypt the block
                let block_generic = GenericArray::from_mut_slice(&mut block);
                cipher.encrypt_block(block_generic);

                block
            })
            .collect()
    }

    pub fn keygen_user() -> [u8; DGSP_N] {
        let mut seed_user: [u8; DGSP_N] = [0; DGSP_N];
        OsRng.fill_bytes(&mut seed_user);
        seed_user
    }

    pub fn csr(seed_user: &[u8; DGSP_N], b: usize) -> (Vec<[u8; DGSP_N]>, Vec<DGSPWotsRand>) {
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

    pub fn sign(
        message: &[u8],
        seed_user: &[u8; DGSP_N],
        id: u64,
        cid: &[u8],
        wots_rand: DGSPWotsRand,
        cert: DGSPCert,
    ) -> DGSPSignature {
        let wp = WotsPlus::new_from_rand(&wots_rand.wots_adrs_rand, &wots_rand.wots_sgn_seed);
        let (wots_pk, wots_sig) = wp.pk_sign_from_sk_seed(message, seed_user);

        let pi = Self::calculate_pi(&wots_pk, cid);
        let tau = Self::calculate_tau(&wots_pk, &pi, id);

        DGSPSignature {
            wots_sig,
            nu: cert.nu,
            spx_sig: cert.spx_sig,
            wots_rand,
            tau,
        }
    }

    pub fn verify<R: RevokedListInterface>(
        message: &[u8],
        sig: &DGSPSignature,
        revoked_list: &R,
        pk: &DGSPManagerPublicKey,
    ) -> Result<()> {
        if revoked_list.contains(&sig.nu)? {
            return Err(VerificationError::RevokedSignature)?;
        }
        let wp =
            WotsPlus::new_from_rand(&sig.wots_rand.wots_adrs_rand, &sig.wots_rand.wots_sgn_seed);
        let wots_pk = wp.pk_from_sig(&sig.wots_sig, message);
        let spx_msg = Self::prepare_spx_msg(&wots_pk, &sig.nu, &sig.tau);
        SphincsPlus::verify(&sig.spx_sig, &spx_msg, &pk.spx_pk)
    }

    pub fn check_cert(
        id: u64,
        cid: &[u8; DGSP_N],
        wotsplus_public_keys: &[[u8; DGSP_N]],
        certs: &Vec<DGSPCert>,
        pk: &DGSPManagerPublicKey,
    ) -> Result<()> {
        if wotsplus_public_keys.len() != certs.len() {
            return Err(Error::SizeMismatch);
        }

        wotsplus_public_keys
            .into_par_iter()
            .zip(certs.into_par_iter())
            .try_for_each(|(wots_pk, cert)| {
                let pi = Self::calculate_pi(wots_pk, cid);
                let tau = Self::calculate_tau(wots_pk, &pi, id);
                let spx_msg = Self::prepare_spx_msg(wots_pk, &cert.nu, &tau);
                SphincsPlus::verify(&cert.spx_sig, &spx_msg, &pk.spx_pk)
            })
    }

    pub fn judge(sig: &DGSPSignature, message: &[u8], id: u64, pi: &[u8; DGSP_N]) -> Result<()> {
        let wp =
            WotsPlus::new_from_rand(&sig.wots_rand.wots_adrs_rand, &sig.wots_rand.wots_sgn_seed);
        let wots_pk = wp.pk_from_sig(&sig.wots_sig, message);
        if sig.tau != Self::calculate_tau(&wots_pk, pi, id) {
            return Err(Error::WrongIDOpened(id));
        }
        Ok(())
    }
}

#[cfg(all(test, any(feature = "in-disk", feature = "in-memory")))]
mod tests {
    use super::*;
    use crate::VerificationError::SphincsPlusVerificationFailed;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    #[cfg(feature = "in-disk")]
    use crate::db::in_disk::{InDiskPLM, InDiskRevokedList};
    #[cfg(feature = "in-memory")]
    use crate::db::in_memory::{InMemoryPLM, InMemoryRevokedList};

    #[cfg(feature = "in-disk")]
    use std::path::PathBuf;

    #[cfg(feature = "in-disk")]
    use tempfile::Builder;

    fn random_str(length: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    fn random_message() -> Vec<u8> {
        let mut rng = OsRng;
        let length: usize = rng.gen_range(1..=20);
        let mut message = vec![0u8; length];
        rng.fill_bytes(&mut message);
        message
    }

    #[cfg(feature = "in-disk")]
    fn in_disk() -> Result<(InDiskPLM, InDiskRevokedList)> {
        // Create a temporary directory for test in the project root
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let temp_dir = Builder::new()
            .prefix("temp_example_db_")
            .tempdir_in(&project_root)
            .map_err(|_| {
                Error::Custom("Failed to create temporary directory in project root".to_string())
            })?;

        // Create PL_M
        let plm = InDiskPLM::open(temp_dir.path().join("dgsp"))?;
        // Create Revoked List:
        let revoked_list = InDiskRevokedList::open(temp_dir.path().join("dgsp"))?;
        Ok((plm, revoked_list))
    }

    #[cfg(feature = "in-memory")]
    fn in_memory() -> Result<(InMemoryPLM, InMemoryRevokedList)> {
        // Create PL_M
        let plm = InMemoryPLM::open("")?;
        // Create manager keys
        let revoked_list = InMemoryRevokedList::open("")?;
        Ok((plm, revoked_list))
    }

    fn test_dgsp_full<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        // Create manager keys
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        // Create a user and join to DGSP
        let seed = DGSP::keygen_user();
        let username = random_str(10);
        let (id, cid) = DGSP::join(&skm.msk, username.as_str(), &plm).unwrap();

        // Create a batch of CSR
        const B: usize = 3;
        let (mut wots_pks, mut wots_rands) = DGSP::csr(&seed, B);

        // Obtain certificates for the given csr batch
        let mut certs = DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();

        // Make sure the given certificates are correctly created by the manager.
        DGSP::check_cert(id, &cid, &wots_pks, &certs, &pkm).unwrap();

        // Sign a single message
        let message = random_message();

        let wots_rand = wots_rands.pop().unwrap();
        let cert = certs.pop().unwrap();
        let wots_pk = wots_pks.pop().unwrap();
        let sig = DGSP::sign(&message, &seed, id, &cid, wots_rand, cert);

        // Verify the signature
        DGSP::verify(&message, &sig, &revoked_list, &pkm).unwrap();

        // Obtain id, username, and proof from sig
        let pi = DGSP::calculate_pi(&wots_pk, &cid);
        assert_eq!(
            DGSP::open(&skm.msk, &plm, &sig, &message).unwrap(),
            (id, username, pi)
        );

        // Judge the manager and make sure it is following the protocol
        DGSP::judge(&sig, &message, id, &pi).unwrap();

        // Revoke a user and its certificates
        DGSP::revoke(&skm.msk, &plm, &[id], &revoked_list).unwrap();
        assert!(revoked_list.contains(&sig.nu).unwrap());

        for cert in &certs {
            assert!(revoked_list.contains(&cert.nu).unwrap());
        }

        // Make sure no cert will be created for that id from now on.
        let (wots_pks_new, _) = DGSP::csr(&seed, 1);
        assert_eq!(
            DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks_new, &plm, &skm.spx_sk),
            Err(Error::InvalidCertReq)
        );

        // Make sure no signatures created by the revoked user will verify
        let wots_rand_new = wots_rands.pop().unwrap();
        let cert_new = certs.pop().unwrap();
        let message_new = random_message();
        let sig_new = DGSP::sign(&message_new, &seed, id, &cid, wots_rand_new, cert_new);
        assert_eq!(
            DGSP::verify(&message_new, &sig_new, &revoked_list, &pkm),
            Err(Error::VerificationFailed(
                VerificationError::RevokedSignature
            ))
        );
    }

    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_full_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_full(plm, revoked_list);
    }

    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_full_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_full(plm, revoked_list);
    }

    fn test_dgsp_manager_trust<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (mut wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);

        // Test manager with fake credentials:
        let fake_id = 6u64;
        let mut fake_cid = cid_u0;
        fake_cid[0] ^= 1;
        assert!(DGSP::gen_cert(&skm.msk, fake_id, &cid_u0, &wots_pks, &plm, &skm.spx_sk).is_err());
        assert_eq!(
            DGSP::gen_cert(&skm.msk, id_u0, &fake_cid, &wots_pks, &plm, &skm.spx_sk),
            Err(Error::InvalidCertReq)
        );
        assert!(
            DGSP::gen_cert(&skm.msk, fake_id, &fake_cid, &wots_pks, &plm, &skm.spx_sk).is_err()
        );

        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();
        DGSP::check_cert(id_u0, &cid_u0, &wots_pks, &certs, &pkm).unwrap();

        let wots_pk = wots_pks.pop().unwrap();
        let cert = certs.pop().unwrap();
        let pi = DGSP::calculate_pi(&wots_pk, &cid_u0);
        let mut fake_tau = DGSP::calculate_tau(&wots_pk, &pi, id_u0);
        fake_tau[0] ^= 1;

        // Prepare a fake certificate
        let spx_msg_fake = DGSP::prepare_spx_msg(&wots_pk, &cert.nu, &fake_tau);
        let spx_sig_fake = SphincsPlus::sign(&spx_msg_fake, &skm.spx_sk).unwrap();
        let fake_cert = DGSPCert {
            nu: cert.nu,
            spx_sig: spx_sig_fake,
        };
        assert!(matches!(
            DGSP::check_cert(id_u0, &cid_u0, &[wots_pk], &vec!(fake_cert.clone()), &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));

        // Even signing without checking it should never be verified
        let message = random_message();
        let wots_rand = wots_rands.pop().unwrap();
        let sig_fake = DGSP::sign(
            &message,
            &seed_u0,
            id_u0,
            &cid_u0,
            wots_rand.clone(),
            fake_cert,
        );
        assert!(matches!(
            DGSP::verify(&message, &sig_fake, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));

        // Now let's create a valid signature with the correct cert
        let sig = DGSP::sign(&message, &seed_u0, id_u0, &cid_u0, wots_rand, cert);
        DGSP::verify(&message, &sig, &revoked_list, &pkm).unwrap();

        // A new user joins the group
        let username_u1 = "dgsp user 1";
        let (id_u1, _) = DGSP::join(&skm.msk, username_u1, &plm).unwrap();

        assert_eq!(
            DGSP::open(&skm.msk, &plm, &sig, &message).unwrap(),
            (id_u0, username_u0.to_string(), pi)
        );
        DGSP::judge(&sig, &message, id_u0, &pi).unwrap();

        // Assume manager returning a wrong id after opening the signature
        assert_eq!(
            DGSP::judge(&sig, &message, id_u1, &pi),
            Err(Error::WrongIDOpened(id_u1))
        );
    }

    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_manager_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_manager_trust(plm, revoked_list);
    }

    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_manager_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_manager_trust(plm, revoked_list);
    }

    fn test_dgsp_join<P: PLMInterface>(plm: P) {
        let (_, skm) = DGSP::keygen_manager().unwrap();

        let username = random_str(10);
        DGSP::join(&skm.msk, username.as_str(), &plm).unwrap();
        assert_eq!(
            DGSP::join(&skm.msk, username.as_str(), &plm),
            Err(Error::UsernameAlreadyExists(username))
        );
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_join_in_disk() {
        let (plm, _) = in_disk().unwrap();
        test_dgsp_join(plm);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_join_in_memory() {
        let (plm, _) = in_memory().unwrap();
        test_dgsp_join(plm);
    }

    fn test_dgsp_gen_cert<P: PLMInterface>(plm: P) {
        let (_, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, _) = DGSP::csr(&seed_u0, B);
        DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        // Test manager with fake credentials:
        let fake_id = id_u0 ^ 1u64;
        let mut fake_cid = cid_u0;
        fake_cid[0] ^= 1u8;
        assert!(DGSP::gen_cert(&skm.msk, fake_id, &cid_u0, &wots_pks, &plm, &skm.spx_sk).is_err());
        assert_eq!(
            DGSP::gen_cert(&skm.msk, id_u0, &fake_cid, &wots_pks, &plm, &skm.spx_sk),
            Err(Error::InvalidCertReq)
        );
        assert!(
            DGSP::gen_cert(&skm.msk, fake_id, &fake_cid, &wots_pks, &plm, &skm.spx_sk).is_err()
        );

        let username_u1 = "dgsp user 1";
        let (id_u1, cid_u1) = DGSP::join(&skm.msk, username_u1, &plm).unwrap();

        // Test manager with incorrect credentials:
        assert_eq!(
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u1, &wots_pks, &plm, &skm.spx_sk),
            Err(Error::InvalidCertReq)
        );
        assert_eq!(
            DGSP::gen_cert(&skm.msk, id_u1, &cid_u0, &wots_pks, &plm, &skm.spx_sk),
            Err(Error::InvalidCertReq)
        );
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_gen_cert_in_disk() {
        let (plm, _) = in_disk().unwrap();
        test_dgsp_gen_cert(plm);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_gen_cert_in_memory() {
        let (plm, _) = in_memory().unwrap();
        test_dgsp_gen_cert(plm);
    }

    fn test_dgsp_check_cert<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed = DGSP::keygen_user();
        let username = "dgsp user";
        let (id, cid) = DGSP::join(&skm.msk, username, &plm).unwrap();

        const B: usize = 2;
        let (mut wots_pks, mut wots_rands) = DGSP::csr(&seed, B);

        let mut certs = DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
        DGSP::check_cert(id, &cid, &wots_pks, &certs, &pkm).unwrap();

        // Unequal lengths of WOTS+ pk list and certificate list
        let wots_pk = wots_pks.pop().unwrap();
        assert_eq!(
            DGSP::check_cert(id, &cid, &wots_pks, &certs, &pkm),
            Err(Error::SizeMismatch)
        );

        // Prepare a fake certificate
        let pi = DGSP::calculate_pi(&wots_pk, &cid);
        let mut fake_tau = DGSP::calculate_tau(&wots_pk, &pi, id);
        fake_tau[0] ^= 1;

        let cert = certs.pop().unwrap();

        let spx_msg_fake = DGSP::prepare_spx_msg(&wots_pk, &cert.nu, &fake_tau);
        let spx_sig_fake = SphincsPlus::sign(&spx_msg_fake, &skm.spx_sk).unwrap();

        let fake_cert = DGSPCert {
            nu: cert.nu,
            spx_sig: spx_sig_fake,
        };

        assert!(matches!(
            DGSP::check_cert(id, &cid, &[wots_pk], &vec!(fake_cert.clone()), &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));

        // Even signing without checking it should never be verified
        let message = random_message();
        let wots_rand = wots_rands.pop().unwrap();
        let sig_fake = DGSP::sign(&message, &seed, id, &cid, wots_rand, fake_cert);
        assert!(matches!(
            DGSP::verify(&message, &sig_fake, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_check_cert_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_check_cert(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_check_cert_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_check_cert(plm, revoked_list);
    }

    fn test_dgsp_sign<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        let sig_wrong_seed = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, c);
        DGSP::verify(&m, &sig_wrong_seed, &revoked_list, &pkm).unwrap();
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_seed<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        let mut seed_u1 = seed_u0;
        seed_u1[0] ^= 1;

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect seed:
        let sig_wrong_seed = DGSP::sign(&m, &seed_u1, id_u0, &cid_u0, wr, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_seed, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_seed_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_seed(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_seed_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_seed(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_id<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        let username_u1 = "dgsp user 1";
        let (id_u1, _) = DGSP::join(&skm.msk, username_u1, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect id:
        let sig_wrong_id = DGSP::sign(&m, &seed_u0, id_u1, &cid_u0, wr, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_id, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_id_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_id(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_id_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_id(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_cid<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        let username_u1 = "dgsp user 1";
        let (_, cid_u1) = DGSP::join(&skm.msk, username_u1, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect cid:
        let sig_wrong_cid = DGSP::sign(&m, &seed_u0, id_u0, &cid_u1, wr, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_cid, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_cid_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_cid(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_cid_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_cid(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_wots_rand_adrs<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect WOTS+ ADRS random array :
        let wrong_wr_adrs = DGSPWotsRand {
            wots_adrs_rand: {
                let mut fake_wots_adrs_rand = wr.wots_adrs_rand;
                fake_wots_adrs_rand[0] ^= 1;
                fake_wots_adrs_rand
            },
            ..wr
        };
        let sig_wrong_wr_adrs = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wrong_wr_adrs, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_wr_adrs, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_wots_rand_adrs_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_wots_rand_adrs(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_wots_rand_adrs_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_wots_rand_adrs(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_wots_sgn_seed<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect WOTS+ SGN seed :
        let wrong_wr_seed = DGSPWotsRand {
            wots_sgn_seed: {
                let mut fake_wots_sgn_seed = wr.wots_sgn_seed;
                fake_wots_sgn_seed[0] ^= 1;
                fake_wots_sgn_seed
            },
            ..wr
        };
        let sig_wrong_wr_seed = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wrong_wr_seed, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_wr_seed, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_wots_sgn_seed_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_wots_sgn_seed(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_wots_sgn_seed_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_wots_sgn_seed(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_cert_nu<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect certificate nu :
        let wrong_c_nu = DGSPCert {
            nu: {
                let mut fake_nu = c.nu;
                fake_nu[0] ^= 1;
                fake_nu
            },
            ..c
        };
        let sig_wrong_cert_nu = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, wrong_c_nu);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_cert_nu, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_cert_nu_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_cert_nu(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_cert_nu_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_cert_nu(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_cert_spx_sig<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect certificate SPHINCS+ signature :
        let wrong_c_spx = DGSPCert {
            spx_sig: {
                let mut fake_spx_sig = [0u8; SPX_BYTES];
                fake_spx_sig.copy_from_slice(c.spx_sig.as_ref());
                fake_spx_sig[0] ^= 1;
                fake_spx_sig.into()
            },
            ..c
        };
        let sig_wrong_cert_spx = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, wrong_c_spx);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_cert_spx, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_cert_spx_sig_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_cert_spx_sig(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_cert_spx_sig_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_cert_spx_sig(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_message<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, c);

        // Try to forge signature with fake message
        let mut fake_message = m.clone();
        fake_message[0] ^= 1;
        assert!(matches!(
            DGSP::verify(&fake_message, &sig, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_message_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_message(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_message_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_message(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_wots_sig<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, c);

        // Try to forge signature with fake WOTS+ signature
        let sig_fake_wots_sig = DGSPSignature {
            wots_sig: {
                let mut fake_wots_sig = sig.wots_sig;
                fake_wots_sig[0] ^= 1;
                fake_wots_sig
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_wots_sig, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_wots_sig_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_wots_sig(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_wots_sig_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_wots_sig(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_nu<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, c);

        // Try to forge signature with fake certificate nu
        let sig_fake_nu = DGSPSignature {
            nu: {
                let mut fake_nu = sig.nu;
                fake_nu[0] ^= 1;
                fake_nu
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_nu, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_nu_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_nu(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_nu_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_nu(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_spx_sig<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, c);

        // Try to forge signature with fake SPHINCS+ signature
        let sig_fake_spx_sig = DGSPSignature {
            spx_sig: {
                let mut fake_spx_sig = [0u8; SPX_BYTES];
                fake_spx_sig.copy_from_slice(sig.spx_sig.as_ref());
                fake_spx_sig[0] ^= 1;
                fake_spx_sig.into()
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_spx_sig, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_spx_sig_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_spx_sig(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_spx_sig_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_spx_sig(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_wots_adrs_rand<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, c);

        // Try to forge signature with fake WOTS+ ADRS random array
        let sig_fake_wots_adrs_rand = DGSPSignature {
            wots_rand: DGSPWotsRand {
                wots_adrs_rand: {
                    let mut fake_wots_adrs_rand = sig.wots_rand.wots_adrs_rand;
                    fake_wots_adrs_rand[0] ^= 1;
                    fake_wots_adrs_rand
                },
                ..sig.wots_rand
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_wots_adrs_rand, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_wots_adrs_rand_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_wots_adrs_rand(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_wots_adrs_rand_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_wots_adrs_rand(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_wots_sgn_seed<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, c);

        // Try to forge signature with fake WOTS+ SGN seed
        let sig_fake_wots_sgn_seed = DGSPSignature {
            wots_rand: DGSPWotsRand {
                wots_sgn_seed: {
                    let mut fake_wots_sgn_seed = sig.wots_rand.wots_sgn_seed;
                    fake_wots_sgn_seed[0] ^= 1;
                    fake_wots_sgn_seed
                },
                ..sig.wots_rand
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_wots_sgn_seed, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_wots_sgn_seed_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_wots_sgn_seed(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_wots_sgn_seed_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_wots_sgn_seed(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_tau<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, &cid_u0, wr, c);

        // Try to forge signature with fake tau
        let sig_fake_tau = DGSPSignature {
            tau: {
                let mut fake_tau = sig.tau;
                fake_tau[0] ^= 1;
                fake_tau
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_tau, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_tau_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_tau(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_tau_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_tau(plm, revoked_list);
    }

    fn test_dgsp_open<P: PLMInterface>(plm: P) {
        let (_, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (mut wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);

        let mut certs =
            DGSP::gen_cert(&skm.msk, id_u0, &cid_u0, &wots_pks, &plm, &skm.spx_sk).unwrap();

        let wots_pk = wots_pks.pop().unwrap();
        let cert = certs.pop().unwrap();
        let pi = DGSP::calculate_pi(&wots_pk, &cid_u0);

        let message = random_message();
        let wots_rand = wots_rands.pop().unwrap();
        let sig = DGSP::sign(&message, &seed_u0, id_u0, &cid_u0, wots_rand, cert);

        // A new user joins the group
        let username_u1 = "dgsp user 1";
        let (id_u1, _) = DGSP::join(&skm.msk, username_u1, &plm).unwrap();

        assert_eq!(
            DGSP::open(&skm.msk, &plm, &sig, &message).unwrap(),
            (id_u0, username_u0.to_string(), pi)
        );
        DGSP::judge(&sig, &message, id_u0, &pi).unwrap();

        // If a wrong id is given for an opened signature, it won't be accepted.
        assert_eq!(
            DGSP::judge(&sig, &message, id_u1, &pi),
            Err(Error::WrongIDOpened(id_u1))
        );
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_open_in_disk() {
        let (plm, _) = in_disk().unwrap();
        test_dgsp_open(plm);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_open_in_memory() {
        let (plm, _) = in_memory().unwrap();
        test_dgsp_open(plm);
    }
}
