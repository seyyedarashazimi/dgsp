# run_tests.sh
set -e

cargo test test_sphincs_plus --no-default-features --features sphincs_sha2_128f
cargo test test_sphincs_plus --no-default-features --features sphincs_sha2_128s
cargo test test_sphincs_plus --no-default-features --features sphincs_sha2_192f
cargo test test_sphincs_plus --no-default-features --features sphincs_sha2_192s
cargo test test_sphincs_plus --no-default-features --features sphincs_sha2_256f
cargo test test_sphincs_plus --no-default-features --features sphincs_sha2_256s

cargo test test_sphincs_plus --no-default-features --features sphincs_shake_128f
cargo test test_sphincs_plus --no-default-features --features sphincs_shake_128s
cargo test test_sphincs_plus --no-default-features --features sphincs_shake_192f
cargo test test_sphincs_plus --no-default-features --features sphincs_shake_192s
cargo test test_sphincs_plus --no-default-features --features sphincs_shake_256f
cargo test test_sphincs_plus --no-default-features --features sphincs_shake_256s
