use crate::array_struct;
use crate::errors::Error;
use crate::params::{DGSP_N, DGSP_POS_BYTES};
use crate::sphincs_plus::{
    SphincsPlus, SphincsPlusPublicKey, SphincsPlusSecretKey, SphincsPlusSignature,
};
use crate::utils::{bytes_to_usize, u64_to_bytes};
use crate::wots_plus::{WotsPlus, WTS_ADRS_RAND_BYTES};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use std::collections::HashSet;
use zeroize::Zeroize;

#[cfg(feature = "sphincs_sha2_128f")]
use crate::sphincs_plus::params_sphincs_sha2_128f::*;
#[cfg(feature = "sphincs_sha2_128s")]
use crate::sphincs_plus::params_sphincs_sha2_128s::*;
#[cfg(feature = "sphincs_sha2_192f")]
use crate::sphincs_plus::params_sphincs_sha2_192f::*;
#[cfg(feature = "sphincs_sha2_192s")]
use crate::sphincs_plus::params_sphincs_sha2_192s::*;
#[cfg(feature = "sphincs_sha2_256f")]
use crate::sphincs_plus::params_sphincs_sha2_256f::*;
#[cfg(feature = "sphincs_sha2_256s")]
use crate::sphincs_plus::params_sphincs_sha2_256s::*;
#[cfg(feature = "sphincs_shake_128f")]
use crate::sphincs_plus::params_sphincs_shake_128f::*;
#[cfg(feature = "sphincs_shake_128s")]
use crate::sphincs_plus::params_sphincs_shake_128s::*;
#[cfg(feature = "sphincs_shake_192f")]
use crate::sphincs_plus::params_sphincs_shake_192f::*;
#[cfg(feature = "sphincs_shake_192s")]
use crate::sphincs_plus::params_sphincs_shake_192s::*;
#[cfg(feature = "sphincs_shake_256f")]
use crate::sphincs_plus::params_sphincs_shake_256f::*;
#[cfg(feature = "sphincs_shake_256s")]
use crate::sphincs_plus::params_sphincs_shake_256s::*;

#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
use crate::hash::sha2::DGSPHasher;
#[cfg(any(
    feature = "sphincs_shake_128f",
    feature = "sphincs_shake_128s",
    feature = "sphincs_shake_192f",
    feature = "sphincs_shake_192s",
    feature = "sphincs_shake_256f",
    feature = "sphincs_shake_256s",
))]
use crate::hash::shake::DGSPHasher;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

pub struct PLMEntry {
    is_active: bool,
    username: String,
}

#[derive(Default)]
pub struct PLM {
    vec: Vec<PLMEntry>,
    set: HashSet<String>,
}

impl PLM {
    pub fn username_exists(&self, username: &str) -> bool {
        self.set.contains(username)
    }

    pub fn get_username(&self, id: usize) -> String {
        self.vec[id].username.clone()
    }

    pub fn id_is_active(&self, id: usize) -> bool {
        self.vec[id].is_active
    }

    pub fn deactivate_id(&mut self, id: usize) {
        self.vec[id].is_active = false;
    }

    pub fn get_new_id(&self) -> usize {
        self.vec.len()
    }

    pub fn add_new_user(&mut self, username: &str) {
        self.vec.push(PLMEntry {
            is_active: true,
            username: username.to_owned(),
        });
        self.set.insert(username.to_owned());
    }

    pub fn len(&self) -> usize {
        self.vec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }
}

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
    pub fn keygen_manager() -> (
        DGSPManagerPublicKey,
        DGSPManagerSecretKey,
        HashSet<[u8; DGSP_POS_BYTES]>,
    ) {
        let sp = SphincsPlus;
        let (spx_pk, spx_sk) = sp.keygen().expect("failed to run SPHINCS+ keygen");
        let mut msk = DGSPMSK::from([0u8; DGSP_N]);
        OsRng.fill_bytes(&mut msk.0);

        let sk = DGSPManagerSecretKey { msk, spx_sk };
        let pk = DGSPManagerPublicKey { spx_pk };

        (pk, sk, HashSet::new())
    }

    pub fn join(
        msk: &DGSPMSK,
        username: &str,
        plm: &mut PLM,
        ctr_ids: &mut Vec<u64>,
    ) -> Option<(usize, [u8; DGSP_N])> {
        if plm.username_exists(username) {
            return None;
        }

        let new_id = plm.get_new_id();
        plm.add_new_user(username);
        let cid = Self::calculate_cid(msk, new_id);
        ctr_ids.push(0);
        Some((new_id, cid))
    }

    pub fn req_cert(
        msk: &DGSPMSK,
        id: usize,
        cid: [u8; DGSP_N],
        wotsplus_public_keys: &Vec<[u8; SPX_WOTS_PK_BYTES]>,
        plm: &PLM,
        sphincs_plus_secret_key: &SphincsPlusSecretKey,
        ctr_ids: &mut Vec<u64>,
    ) -> Option<Vec<([u8; DGSP_POS_BYTES], SphincsPlusSignature)>> {
        if !Self::is_req_valid(msk, id, &cid, plm) {
            return None;
        }
        Some(Self::generate_certificates(
            msk,
            id,
            wotsplus_public_keys,
            &mut ctr_ids[id],
            sphincs_plus_secret_key,
        ))
    }

    pub fn generate_certificates(
        msk: &DGSPMSK,
        id: usize,
        wotsplus_public_keys: &Vec<[u8; SPX_WOTS_PK_BYTES]>,
        ctr_id: &mut u64,
        sphincs_plus_sk: &SphincsPlusSecretKey,
    ) -> Vec<([u8; DGSP_POS_BYTES], SphincsPlusSignature)> {
        // Initialize AES-256 cipher
        let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));

        let s: Vec<([u8; DGSP_POS_BYTES], SphincsPlusSignature)> = wotsplus_public_keys
            .par_iter()
            .enumerate()
            .map(|(i, wots_pk)| {
                let mut pos = [0u8; DGSP_POS_BYTES];

                // Combine id and ctr + i into the input block
                pos[..8].copy_from_slice(&u64_to_bytes(id as u64));
                pos[8..].copy_from_slice(&u64_to_bytes(*ctr_id + (i as u64)));

                // Encrypt the DGSP.pos
                let block_generic = GenericArray::from_mut_slice(&mut pos);
                cipher.encrypt_block(block_generic);

                let mut message = [0u8; SPX_WOTS_PK_BYTES + 16];

                // Combine wots_pk and dgsp.pos into the input message block
                message[..SPX_WOTS_PK_BYTES].copy_from_slice(wots_pk);
                message[SPX_WOTS_PK_BYTES..].copy_from_slice(&pos);

                (pos, SphincsPlus.sign(&message, sphincs_plus_sk).unwrap())
            })
            .collect();

        *ctr_id += wotsplus_public_keys.len() as u64;
        s
    }

    pub fn revoke(
        msk: &DGSPMSK,
        plm: &mut PLM,
        to_be_revoked: Vec<usize>,
        ctr_ids: &mut Vec<u64>,
        revoked_list: &mut HashSet<[u8; DGSP_POS_BYTES]>,
    ) {
        to_be_revoked.iter().for_each(|&r| {
            if r < plm.len() && plm.id_is_active(r) {
                let pos_list = Self::par_dgsp_pos(msk, r, 0, ctr_ids[r] as usize);
                pos_list.into_iter().for_each(|pos| {
                    revoked_list.insert(pos);
                });
                plm.deactivate_id(r);
            }
        });
    }

    pub fn open(msk: &DGSPMSK, plm: &PLM, sig: &DGSPSignature) -> Option<usize> {
        let mut pos = sig.pos;
        let block = GenericArray::from_mut_slice(&mut pos);

        // Initialize cipher
        let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));
        // Decrypt the block
        cipher.decrypt_block(block);

        let id: usize = bytes_to_usize(&pos[..8]);
        if id < plm.len() {
            return Some(id);
        }
        None
    }

    fn calculate_cid(msk: &DGSPMSK, id: usize) -> [u8; DGSP_N] {
        let mut cid = [0u8; DGSP_N];
        DGSPHasher::calc_cid(cid.as_mut(), msk.as_ref(), &u64_to_bytes(id as u64));
        cid
    }

    fn is_req_valid(msk: &DGSPMSK, id: usize, cid: &[u8; DGSP_N], plm: &PLM) -> bool {
        // check if user exists
        if id >= plm.len() {
            return false;
        }
        // check if user is active
        if !plm.id_is_active(id) {
            return false;
        }
        // check if user cid is correct
        if *cid != Self::calculate_cid(msk, id) {
            return false;
        }
        true
    }

    fn par_dgsp_pos(msk: &DGSPMSK, id: usize, ctr_id: u64, b: usize) -> Vec<[u8; DGSP_POS_BYTES]> {
        // Perform parallel encryption
        (0..b)
            .into_par_iter()
            .map(|i| {
                let mut block = [0u8; DGSP_POS_BYTES];

                // Combine pk and ctr + i into the input block
                block[..8].copy_from_slice(&u64_to_bytes(id as u64));
                block[8..].copy_from_slice(&u64_to_bytes(ctr_id + (i as u64)));

                // Initialize AES-256 cipher
                let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));

                // Encrypt the block
                let block_generic = GenericArray::from_mut_slice(&mut block);
                cipher.encrypt_block(block_generic);

                block
            })
            .collect()
    }

    #[allow(unused)]
    fn par_sphincs_plus_sign(
        spx_sk: &SphincsPlusSecretKey,
        wotsplus_public_keys: Vec<[u8; SPX_WOTS_PK_BYTES]>,
        dgsp_pos: &Vec<[u8; DGSP_POS_BYTES]>,
    ) {
        let encrypted: Vec<SphincsPlusSignature> = wotsplus_public_keys
            .par_iter()
            .zip(dgsp_pos.par_iter())
            .map(|(wots_pk, pos)| {
                let mut message = [0u8; SPX_WOTS_PK_BYTES + 16];

                // Combine pk and ctr + i into the input block
                message[..SPX_WOTS_PK_BYTES].copy_from_slice(wots_pk);
                message[SPX_WOTS_PK_BYTES..].copy_from_slice(pos);

                SphincsPlus.sign(&message, spx_sk).unwrap()
            })
            .collect();
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

    pub fn verify(
        message: &[u8],
        sig: &DGSPSignature,
        revoked_list: &HashSet<[u8; DGSP_POS_BYTES]>,
        pk: &DGSPManagerPublicKey,
    ) -> bool {
        if revoked_list.contains(&sig.pos) {
            return false;
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

        SphincsPlus
            .verify(&sig.spx_sig, &spx_msg, &pk.spx_pk)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_dgsp() {
        let mut plm = PLM::default();
        let mut ctr_ids: Vec<u64> = Vec::new();

        // Create manager keys
        let (pk_m, sk_m, revoked_list) = DGSP::keygen_manager();

        // Create user u1 and join
        let seed_u1 = DGSP::keygen_user();
        let username_u1 = "DGSP User 1";
        let (id_u1, cid_u1) = DGSP::join(&sk_m.msk, username_u1, &mut plm, &mut ctr_ids).unwrap();

        // Create a batch of CSR
        const B: usize = 10;
        let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u1, B);

        // Obtain certificates for the given csr batch
        let mut certs = DGSP::req_cert(
            &sk_m.msk,
            id_u1,
            cid_u1,
            &wots_pks,
            &plm,
            &sk_m.spx_sk,
            &mut ctr_ids,
        )
        .unwrap();

        // Sign a single message
        let mut rng = thread_rng();
        let len: u8 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
        let wots_rand = wots_rands.pop().unwrap();
        let cert = certs.pop().unwrap();
        let wots_sig = DGSP::sign(&message, &wots_rand, &seed_u1, cert);

        // Verify the signature
        assert!(DGSP::verify(&message, &wots_sig, &revoked_list, &pk_m));
    }
}
