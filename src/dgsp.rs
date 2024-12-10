use crate::params::{DGSP_BYTES, DGSP_N, DGSP_PK_BYTES, DGSP_POS_BYTES, DGSP_SK_BYTES};
use crate::sphincs_plus::{SphincsPlus, SphincsPlusSecretKey, SphincsPlusSignature};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;

#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
use crate::hash::sha2::DgspHasher;

use crate::sphincs_plus::params_sphincs_sha2_128f::{
    SPX_BYTES, SPX_N, SPX_PK_BYTES, SPX_WOTS_BYTES, SPX_WOTS_PK_BYTES,
};
use crate::utils::{bytes_to_usize, u64_to_bytes, usize_to_bytes};
use crate::wots_plus::{WotsPlus, WTS_ADRS_RAND_BYTES};
#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
use sha2::Digest;

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

#[derive(Default)]
pub struct DGSPManager;

impl DGSPManager {
    pub fn new() -> Self {
        DGSPManager
    }

    pub fn keygen() -> ([u8; DGSP_PK_BYTES], [u8; DGSP_SK_BYTES]) {
        let mut sk = [0u8; DGSP_SK_BYTES];

        let sp = SphincsPlus;

        let (pk_sp, sk_sp) = sp.keygen().expect("failed to run SPHINCS+ keygen");

        OsRng.fill_bytes(&mut sk[..DGSP_N]); // msk
        sk[DGSP_N..].copy_from_slice(&sk_sp.as_ref()[..2 * SPX_N]);

        (pk_sp.as_ref().try_into().unwrap(), sk)
    }

    pub fn join(
        msk: &[u8; DGSP_N],
        username: &str,
        plm: &mut Vec<PLMEntry>,
    ) -> (usize, [u8; DGSP_N]) {
        let new_id = plm.len();
        plm.push(PLMEntry::new(true, username.to_string()));
        let cid = Self::calculate_cid(msk, new_id);
        (new_id, cid)
    }

    pub fn req(
        msk: &[u8; DGSP_N],
        id: usize,
        cid: [u8; DGSP_N],
        wotsplus_public_keys: Vec<[u8; SPX_WOTS_PK_BYTES]>,
        plm: &Vec<PLMEntry>,
        sphincs_plus_secret_key: &SphincsPlusSecretKey,
        ctr_ids: &mut Vec<u64>,
    ) -> Option<Vec<([u8; 16], SphincsPlusSignature)>> {
        if !Self::is_req_valid(msk, id, cid, plm) {
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
        msk: &[u8; DGSP_N],
        id: usize,
        wotsplus_public_keys: Vec<[u8; SPX_WOTS_PK_BYTES]>,
        ctr_id: &mut u64,
        sphincs_plus_sk: &SphincsPlusSecretKey,
    ) -> Vec<([u8; 16], SphincsPlusSignature)> {
        // Initialize AES-256 cipher
        let cipher = Aes256::new(GenericArray::from_slice(msk));

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
        msk: &[u8; DGSP_N],
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

    pub fn open(msk: &[u8; DGSP_N], plm: &mut Vec<PLMEntry>, dgsp_pos: &[u8; 16]) -> Option<usize> {
        // todo: extract pos from sig_dgsp
        // fixme: shouldn't check if the sig is valid or not?
        let mut pos: [u8; 16] = dgsp_pos.as_slice().try_into().unwrap();
        let block = GenericArray::from_mut_slice(&mut pos);

        // Initialize cipher
        let cipher = Aes256::new(GenericArray::from_slice(msk));
        cipher.decrypt_block(block);

        let id: usize = bytes_to_usize(&pos[8..]);
        if id < plm.len() {
            return Some(id);
        }
        None
    }

    fn calculate_cid(msk: &[u8; DGSP_N], id: usize) -> [u8; DGSP_N] {
        let mut hasher = DgspHasher::hasher();
        hasher.update(msk);
        hasher.update(usize_to_bytes(id));
        hasher.finalize().as_slice().try_into().unwrap()
    }

    fn is_req_valid(msk: &[u8; DGSP_N], id: usize, cid: [u8; DGSP_N], plm: &[PLMEntry]) -> bool {
        // check if user exists
        if id >= plm.len() {
            return false;
        }
        // check if user is active
        if !plm[id].is_active {
            return false;
        }
        // check if user cid is correct
        if cid != Self::calculate_cid(msk, id) {
            return false;
        }
        true
    }

    fn par_dgsp_pos(msk: &[u8; DGSP_N], id: usize, ctr_id: u64, b: usize) -> Vec<[u8; 16]> {
        // Perform parallel encryption
        (0..b)
            .into_par_iter()
            .map(|i| {
                let mut block = [0u8; 16];

                // Combine pk and ctr + i into the input block
                block[..8].copy_from_slice(&u64_to_bytes(id as u64));
                block[8..].copy_from_slice(&u64_to_bytes(ctr_id + (i as u64)));

                // Initialize AES-256 cipher
                let cipher = Aes256::new(GenericArray::from_slice(msk));

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

pub struct CSREntry {
    wp_adrs_rand: [u8; 8],
}

#[derive(Default)]
pub struct DGSPUser;

impl DGSPUser {
    pub fn new() -> Self {
        DGSPUser
    }

    pub fn cert_sign_req(
        &self,
        sk_seed_user: &[u8; SPX_N],
        pub_seed_user: &[u8; SPX_N],
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

    pub fn sign_with_pk(
        &self,
        message: &[u8],
        sk_seed_user: &[u8; SPX_N],
        pub_seed_user: &[u8; SPX_N],
        wots_adrs_rand: &[u8; 8],
        cert: ([u8; 16], SphincsPlusSignature),
    ) -> ([u8; DGSP_BYTES], [u8; SPX_WOTS_BYTES]) {
        let wp = WotsPlus::new_from_rand(wots_adrs_rand, pub_seed_user);
        let (wots_sig, wots_pk) = wp.sign_and_pk(message, sk_seed_user);
        let mut sig = [0u8; DGSP_BYTES];
        sig[..SPX_WOTS_BYTES].copy_from_slice(&wots_sig);
        sig[SPX_WOTS_BYTES..SPX_WOTS_BYTES + DGSP_POS_BYTES].copy_from_slice(&cert.0);
        sig[SPX_WOTS_BYTES + DGSP_POS_BYTES..SPX_WOTS_BYTES + DGSP_POS_BYTES + SPX_BYTES]
            .copy_from_slice(cert.1.as_ref());
        sig[DGSP_BYTES - WTS_ADRS_RAND_BYTES..].copy_from_slice(&wp.adrs_rand);
        (sig, wots_pk)
    }

    pub fn verify(
        &self,
        message: &[u8],
        sig: &[u8; DGSP_BYTES],
        wots_pk: &[u8; SPX_WOTS_BYTES],
        pub_seed_user: &[u8; SPX_N],
        revoked_list: &Vec<[u8; 16]>,
        spx_pk: &[u8; SPX_PK_BYTES],
    ) -> bool {
        let mut wots_sig = [0u8; SPX_WOTS_BYTES];
        let mut dgsp_pos = [0u8; DGSP_POS_BYTES];
        let mut spx_sig = [0u8; SPX_BYTES];
        let mut wots_adrs_rand = [0u8; WTS_ADRS_RAND_BYTES];

        wots_sig.copy_from_slice(sig[..SPX_WOTS_BYTES].as_ref());
        dgsp_pos.copy_from_slice(sig[SPX_WOTS_BYTES..SPX_WOTS_BYTES + DGSP_POS_BYTES].as_ref());
        spx_sig.copy_from_slice(
            sig[SPX_WOTS_BYTES + DGSP_POS_BYTES..SPX_WOTS_BYTES + DGSP_POS_BYTES + SPX_BYTES]
                .as_ref(),
        );
        wots_adrs_rand.copy_from_slice(sig[DGSP_BYTES - WTS_ADRS_RAND_BYTES..].as_ref());

        if revoked_list.contains(&dgsp_pos) {
            return false;
        }

        let wp = WotsPlus::new_from_rand(&wots_adrs_rand, pub_seed_user);

        // fixme: shouldn't we verify the wots sig as well like the below?
        if !wp.verify(&wots_sig, message, wots_pk) {
            return false;
        }

        let mut spx_msg = [0u8; SPX_WOTS_BYTES + DGSP_POS_BYTES];
        spx_msg.copy_from_slice(sig[..SPX_WOTS_BYTES + DGSP_POS_BYTES].as_ref());

        if SphincsPlus
            .verify(
                &spx_sig.as_ref().try_into().unwrap(),
                &spx_msg,
                &spx_pk.as_ref().try_into().unwrap(),
            )
            .is_err()
        {
            return false;
        }
        true
    }
}
