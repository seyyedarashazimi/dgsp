pub mod dgsp;
pub mod errors;
pub mod group;
pub mod keygen;
pub mod params;
pub mod sha2_offsets;
pub mod sign;
pub mod sphincs_plus;
pub mod utils;
pub mod verify;
pub mod wots_plus;
// pub use keygen::{generate_group_keys, generate_member_keys};
// pub use sign::sign_message;
// pub use verify::verify_signature;
// pub use group::{add_member, remove_member};

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
