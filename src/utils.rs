use rand::rngs::OsRng;
use rand::RngCore;

pub fn random_bytes(num_bytes: usize) -> Vec<u8> {
    let mut random_bytes = vec![0u8; num_bytes];
    OsRng.fill_bytes(&mut random_bytes);
    random_bytes
}
