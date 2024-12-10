#![allow(dead_code)]

use rand::rngs::OsRng;
use rand::RngCore;

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
