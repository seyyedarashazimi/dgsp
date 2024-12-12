use crate::array_struct;
use crate::errors::Error;
use crate::params::{DGSP_N, DGSP_POS_BYTES};
use crate::sphincs_plus::params_sphincs_sha2_128f::{SPX_N, SPX_WOTS_BYTES, SPX_WOTS_PK_BYTES};
use crate::sphincs_plus::{
    SphincsPlus, SphincsPlusPublicKey, SphincsPlusSecretKey, SphincsPlusSignature,
};
use crate::utils::{bytes_to_usize, u64_to_bytes, usize_to_bytes};
use crate::wots_plus::WotsPlus;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use zeroize::Zeroize;

#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
use crate::hash::sha2::DgspHasher;
#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
use sha2::Digest;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

pub struct PLMEntry {
    is_active: bool,
    username: String,
}

impl PLMEntry {
    pub fn new(is_active: bool, username: String) -> PLMEntry {
        PLMEntry {
            is_active,
            username,
        }
    }
}

pub struct CSREntry {
    wots_adrs_rand: [u8; 8],
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
    pub wots_sig: [u8; SPX_WOTS_BYTES], // todo: zeroize wots data
    pub pos: [u8; DGSP_POS_BYTES],
    pub spx_sig: SphincsPlusSignature,
    pub wots_adrs_rand: [u8; 8],
}

#[derive(Default)]
pub struct DGSPManager;

impl DGSPManager {
    pub fn new() -> Self {
        DGSPManager
    }

    pub fn keygen() -> (DGSPManagerPublicKey, DGSPManagerSecretKey, Vec<[u8; 16]>) {
        let sp = SphincsPlus;
        let (spx_pk, spx_sk) = sp.keygen().expect("failed to run SPHINCS+ keygen");
        let mut msk = DGSPMSK::from([0u8; DGSP_N]);
        OsRng.fill_bytes(&mut msk.0);

        let sk = DGSPManagerSecretKey { msk, spx_sk };
        let pk = DGSPManagerPublicKey { spx_pk };

        (pk, sk, Vec::new())
    }

    pub fn join(
        msk: &DGSPMSK,
        username: &str,
        plm: &mut Vec<PLMEntry>,
        ctr_ids: &mut Vec<u64>,
    ) -> (usize, [u8; DGSP_N]) {
        let new_id = plm.len();
        plm.push(PLMEntry::new(true, username.to_string()));
        let cid = Self::calculate_cid(msk, new_id);
        ctr_ids.push(0);
        (new_id, cid)
    }

    pub fn req(
        msk: &DGSPMSK,
        id: usize,
        cid: [u8; DGSP_N],
        wotsplus_public_keys: &Vec<[u8; SPX_WOTS_PK_BYTES]>,
        plm: &Vec<PLMEntry>,
        sphincs_plus_secret_key: &SphincsPlusSecretKey,
        ctr_ids: &mut Vec<u64>,
    ) -> Option<Vec<([u8; 16], SphincsPlusSignature)>> {
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
    ) -> Vec<([u8; 16], SphincsPlusSignature)> {
        // Initialize AES-256 cipher
        let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));

        let s: Vec<([u8; 16], SphincsPlusSignature)> = wotsplus_public_keys
            .par_iter()
            .enumerate()
            .map(|(i, wots_pk)| {
                let mut pos = [0u8; 16];

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
        plm: &mut Vec<PLMEntry>,
        to_be_revoked: Vec<usize>,
        ctr_ids: &mut Vec<u64>,
        revoked_list: &mut Vec<[u8; 16]>,
    ) {
        to_be_revoked.iter().for_each(|&r| {
            if let Some(p) = plm.get_mut(r) {
                p.is_active = false;
                let mut pos_list = Self::par_dgsp_pos(msk, r, 0, ctr_ids[r] as usize);
                revoked_list.append(&mut pos_list);
            }
        });
    }

    pub fn open(msk: &DGSPMSK, plm: &mut Vec<PLMEntry>, dgsp_pos: &[u8; 16]) -> Option<usize> {
        // todo: extract pos from sig_dgsp
        // fixme: shouldn't check if the sig is valid or not?
        let mut pos: [u8; 16] = dgsp_pos.as_slice().try_into().unwrap();
        let block = GenericArray::from_mut_slice(&mut pos);

        // Initialize cipher
        let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));
        cipher.decrypt_block(block);

        let id: usize = bytes_to_usize(&pos[8..]);
        if id < plm.len() {
            return Some(id);
        }
        None
    }

    fn calculate_cid(msk: &DGSPMSK, id: usize) -> [u8; DGSP_N] {
        let mut hasher = DgspHasher::hasher();
        hasher.update(msk.as_ref());
        hasher.update(usize_to_bytes(id));
        hasher.finalize().as_slice().try_into().unwrap()
    }

    fn is_req_valid(msk: &DGSPMSK, id: usize, cid: &[u8; DGSP_N], plm: &[PLMEntry]) -> bool {
        // check if user exists
        if id >= plm.len() {
            return false;
        }
        // check if user is active
        if !plm[id].is_active {
            return false;
        }
        // check if user cid is correct
        if *cid != Self::calculate_cid(msk, id) {
            return false;
        }
        true
    }

    fn par_dgsp_pos(msk: &DGSPMSK, id: usize, ctr_id: u64, b: usize) -> Vec<[u8; 16]> {
        // Perform parallel encryption
        (0..b)
            .into_par_iter()
            .map(|i| {
                let mut block = [0u8; 16];

                // Combine pk and ctr + i into the input block
                block[..8].copy_from_slice(&u64_to_bytes(id as u64));
                block[8..].copy_from_slice(&u64_to_bytes(ctr_id + (i as u64)));

                // Initialize AES-256 cipher
                let cipher = Aes256::new(GenericArray::from_slice(msk.as_ref()));

                // Encrypt the block
                let mut block_generic = GenericArray::from_mut_slice(&mut block);
                cipher.encrypt_block(&mut block_generic);

                block
            })
            .collect()
    }

    #[allow(unused)]
    fn par_sphincs_plus_sign(
        spx_sk: &SphincsPlusSecretKey,
        wotsplus_public_keys: Vec<[u8; SPX_WOTS_PK_BYTES]>,
        dgsp_pos: &Vec<[u8; 16]>,
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
}

#[derive(Default)]
pub struct DGSPUser;

impl DGSPUser {
    pub fn new() -> Self {
        DGSPUser
    }

    pub fn keygen_user() -> ([u8; SPX_N], [u8; SPX_N]) {
        let mut pk_seed_user: [u8; SPX_N] = [0; 16];
        let mut sk_seed_user: [u8; SPX_N] = [0; 16];
        OsRng.fill_bytes(&mut pk_seed_user);
        OsRng.fill_bytes(&mut sk_seed_user);
        (pk_seed_user, sk_seed_user)
    }

    pub fn cert_sign_req(
        pub_seed_user: &[u8; SPX_N],
        sk_seed_user: &[u8; SPX_N],
        b: usize,
    ) -> (Vec<[u8; SPX_WOTS_PK_BYTES]>, Vec<[u8; 8]>) {
        (0..b)
            .into_par_iter()
            .map(|_| {
                let mut wp = WotsPlus::new(pub_seed_user);
                let (pk_wots, _) = wp.keygen(sk_seed_user);

                (pk_wots, wp.adrs_rand)
            })
            .unzip()
    }

    pub fn sign(
        message: &[u8],
        pub_seed_user: &[u8; SPX_N],
        sk_seed_user: &[u8; SPX_N],
        wots_adrs_rand: &[u8; 8],
        cert: ([u8; 16], SphincsPlusSignature),
    ) -> DGSPSignature {
        let wp = WotsPlus::new_from_rand(wots_adrs_rand, pub_seed_user);
        let (wots_sig, _) = wp.sign_and_pk(message, sk_seed_user);

        DGSPSignature {
            wots_sig,
            pos: cert.0,
            spx_sig: cert.1,
            wots_adrs_rand: *wots_adrs_rand,
        }
    }

    // pub fn sign_and_pk(
    //     message: &[u8],
    //     pub_seed_user: &[u8; SPX_N],
    //     sk_seed_user: &[u8; SPX_N],
    //     wots_adrs_rand: &[u8; 8],
    //     cert: ([u8; 16], SphincsPlusSignature),
    // ) -> ([u8; DGSP_BYTES], [u8; SPX_WOTS_BYTES]) {
    //     let wp = WotsPlus::new_from_rand(wots_adrs_rand, pub_seed_user);
    //     let (wots_sig, wots_pk) = wp.sign_and_pk(message, sk_seed_user);
    //     let mut sig = [0u8; DGSP_BYTES];
    //     sig[..SPX_WOTS_BYTES].copy_from_slice(&wots_sig);
    //     sig[SPX_WOTS_BYTES..SPX_WOTS_BYTES + DGSP_POS_BYTES].copy_from_slice(&cert.0);
    //     sig[SPX_WOTS_BYTES + DGSP_POS_BYTES..SPX_WOTS_BYTES + DGSP_POS_BYTES + SPX_BYTES]
    //         .copy_from_slice(cert.1.as_ref());
    //     sig[DGSP_BYTES - WTS_ADRS_RAND_BYTES..].copy_from_slice(&wp.adrs_rand);
    //     (sig, wots_pk)
    // }

    pub fn verify(
        message: &[u8],
        sig: &DGSPSignature,
        wots_pk: &[u8; SPX_WOTS_BYTES],
        pub_seed_user: &[u8; SPX_N],
        revoked_list: &Vec<[u8; 16]>,
        spx_pk: &SphincsPlusPublicKey,
    ) -> bool {
        // let mut wots_sig = [0u8; SPX_WOTS_BYTES];
        // let mut dgsp_pos = [0u8; DGSP_POS_BYTES];
        // let mut spx_sig = [0u8; SPX_BYTES];
        // let mut wots_adrs_rand = [0u8; WTS_ADRS_RAND_BYTES];

        // wots_sig.copy_from_slice(sig[..SPX_WOTS_BYTES].as_ref());
        // dgsp_pos.copy_from_slice(sig[SPX_WOTS_BYTES..SPX_WOTS_BYTES + DGSP_POS_BYTES].as_ref());
        // spx_sig.copy_from_slice(
        //     sig[SPX_WOTS_BYTES + DGSP_POS_BYTES..SPX_WOTS_BYTES + DGSP_POS_BYTES + SPX_BYTES]
        //         .as_ref(),
        // );
        // wots_adrs_rand.copy_from_slice(sig[DGSP_BYTES - WTS_ADRS_RAND_BYTES..].as_ref());

        if revoked_list.contains(&sig.pos) {
            return false;
        }

        let wp = WotsPlus::new_from_rand(&sig.wots_adrs_rand, pub_seed_user);

        // fixme: shouldn't we verify the wots sig as well like the below?
        if !wp.verify(&sig.wots_sig, message, wots_pk) {
            return false;
        }

        let mut spx_msg = [0u8; SPX_WOTS_PK_BYTES + DGSP_POS_BYTES];
        spx_msg[..SPX_WOTS_PK_BYTES].copy_from_slice(wots_pk);
        spx_msg[SPX_WOTS_PK_BYTES..].copy_from_slice(sig.pos.as_ref());

        SphincsPlus.verify(&sig.spx_sig, &spx_msg, spx_pk).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_dgsp() {
        let mut plm: Vec<PLMEntry> = Vec::new();
        let mut ctr_ids: Vec<u64> = Vec::new();

        // Create manager
        let (pk_m, sk_m, mut revoked_list) = DGSPManager::keygen();

        // Create user u1 and join
        let (pk_seed_u1, sk_seed_u1) = DGSPUser::keygen_user();
        let username_u1 = "DGSP User 1";
        let (id_u1, cid_u1) = DGSPManager::join(&sk_m.msk, username_u1, &mut plm, &mut ctr_ids);

        // Create a batch of CSR
        const B: usize = 10;
        let (mut wots_pks, mut wots_adrs_rands) =
            DGSPUser::cert_sign_req(&pk_seed_u1, &sk_seed_u1, B);

        // Obtain certificates for the given csr batch
        let mut certs = DGSPManager::req(
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
        let len: u16 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
        let wots_adrs_rand = wots_adrs_rands.pop().unwrap();
        let wots_pk = wots_pks.pop().unwrap();
        let cert = certs.pop().unwrap();
        let wots_sig = DGSPUser::sign(&message, &pk_seed_u1, &sk_seed_u1, &wots_adrs_rand, cert);

        // Verify the signature
        assert!(DGSPUser::verify(
            &message,
            &wots_sig,
            &wots_pk,
            &pk_seed_u1,
            &revoked_list,
            &pk_m.spx_pk,
        ));
    }
}
