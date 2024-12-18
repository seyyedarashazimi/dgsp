# run_tests.sh
set -e

cargo test test_dgsp --no-default-features --features sphincs_sha2_128f,in-memory
cargo test test_dgsp --no-default-features --features sphincs_sha2_128s,in-memory
cargo test test_dgsp --no-default-features --features sphincs_sha2_192f,in-memory
cargo test test_dgsp --no-default-features --features sphincs_sha2_192s,in-memory
cargo test test_dgsp --no-default-features --features sphincs_sha2_256f,in-memory
cargo test test_dgsp --no-default-features --features sphincs_sha2_256s,in-memory

cargo test test_dgsp --no-default-features --features sphincs_shake_128f,in-memory
cargo test test_dgsp --no-default-features --features sphincs_shake_128s,in-memory
cargo test test_dgsp --no-default-features --features sphincs_shake_192f,in-memory
cargo test test_dgsp --no-default-features --features sphincs_shake_192s,in-memory
cargo test test_dgsp --no-default-features --features sphincs_shake_256f,in-memory
cargo test test_dgsp --no-default-features --features sphincs_shake_256s,in-memory


cargo test test_dgsp --no-default-features --features sphincs_sha2_128f,in-disk
cargo test test_dgsp --no-default-features --features sphincs_sha2_128s,in-disk
cargo test test_dgsp --no-default-features --features sphincs_sha2_192f,in-disk
cargo test test_dgsp --no-default-features --features sphincs_sha2_192s,in-disk
cargo test test_dgsp --no-default-features --features sphincs_sha2_256f,in-disk
cargo test test_dgsp --no-default-features --features sphincs_sha2_256s,in-disk

cargo test test_dgsp --no-default-features --features sphincs_shake_128f,in-disk
cargo test test_dgsp --no-default-features --features sphincs_shake_128s,in-disk
cargo test test_dgsp --no-default-features --features sphincs_shake_192f,in-disk
cargo test test_dgsp --no-default-features --features sphincs_shake_192s,in-disk
cargo test test_dgsp --no-default-features --features sphincs_shake_256f,in-disk
cargo test test_dgsp --no-default-features --features sphincs_shake_256s,in-disk