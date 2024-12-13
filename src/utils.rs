#![allow(dead_code)]

use rand::rngs::OsRng;
use rand::RngCore;

#[macro_export]
macro_rules! array_struct {
    ($type: ident, $size: expr) => {
        /// `$type` securely holds data, using a `u8; $size` internal field.
        /// This struct implements `Zeroize`, ensuring the data is wiped from memory when dropped
        /// (`#[zeroize(drop)]`).
        /// Cloning is supported but should be done cautiously, as it duplicates sensitive
        /// information in memory.
        /// It also provide serialization via the `serialization` feature.
        #[derive(Clone, Debug, Zeroize)]
        #[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
        pub struct $type(
            #[cfg_attr(feature = "serialization", serde(with = "BigArray"))] [u8; $size],
        );

        impl AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<[u8; $size]> for $type {
            fn from(value: [u8; $size]) -> Self {
                Self(value)
            }
        }

        impl TryFrom<&[u8]> for $type {
            type Error = Error;
            fn try_from(data: &[u8]) -> Result<$type, Error> {
                if data.len() != $size {
                    Err(Error::BadLength($size, data.len()))
                } else {
                    let mut array = [0u8; $size];
                    array.copy_from_slice(data);
                    Ok($type(array))
                }
            }
        }

        impl PartialEq for $type {
            /// By no means constant time comparison
            fn eq(&self, other: &Self) -> bool {
                self.0
                    .iter()
                    .zip(other.0.iter())
                    .try_for_each(|(a, b)| if a == b { Ok(()) } else { Err(()) })
                    .is_ok()
            }
        }
    };
}

pub(crate) fn random_bytes(num_bytes: usize) -> Vec<u8> {
    let mut random_bytes = vec![0u8; num_bytes];
    OsRng.fill_bytes(&mut random_bytes);
    random_bytes
}

pub(crate) fn u32_to_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub(crate) fn u64_to_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub(crate) fn usize_to_bytes(value: usize) -> [u8; 8] {
    value.to_be_bytes()
}

pub(crate) fn bytes_to_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(
        bytes
            .try_into()
            .expect("Index out of bounds or incorrect length"),
    )
}

pub(crate) fn bytes_to_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(
        bytes
            .try_into()
            .expect("Index out of bounds or incorrect length"),
    )
}

pub(crate) fn bytes_to_usize(bytes: &[u8]) -> usize {
    usize::from_be_bytes(
        bytes
            .try_into()
            .expect("Index out of bounds or incorrect length"),
    )
}

pub(crate) fn get_byte_at(array: &[u8], index: usize) -> u8 {
    array[index]
}

pub(crate) fn get_u32_at(array: &[u8], start_index: usize) -> u32 {
    bytes_to_u32(&array[start_index..start_index + 4])
}

pub(crate) fn get_u64_at(array: &[u8], start_index: usize) -> u64 {
    bytes_to_u64(&array[start_index..start_index + 8])
}

pub(crate) fn set_byte_at(array: &mut [u8], value: u8, index: usize) {
    array[index] = value;
}

pub(crate) fn set_u32_at(array: &mut [u8], value: u32, start_index: usize) {
    array[start_index..start_index + 4].copy_from_slice(&u32_to_bytes(value));
}

pub(crate) fn set_u64_at(array: &mut [u8], value: u64, start_index: usize) {
    array[start_index..start_index + 8].copy_from_slice(&u64_to_bytes(value));
}
