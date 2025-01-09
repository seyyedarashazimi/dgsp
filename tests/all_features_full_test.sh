#!/bin/bash
set -e

sphincs_features=(
  "sphincs_sha2_128f"
  "sphincs_sha2_128s"
  "sphincs_sha2_192f"
  "sphincs_sha2_192s"
  "sphincs_sha2_256f"
  "sphincs_sha2_256s"
  "sphincs_shake_128f"
  "sphincs_shake_128s"
  "sphincs_shake_192f"
  "sphincs_shake_192s"
  "sphincs_shake_256f"
  "sphincs_shake_256s"
)

storage_features=("in-disk" "in-memory")

for sphincs in "${sphincs_features[@]}"; do
  for storage in "${storage_features[@]}"; do
    echo "Testing with features: $sphincs, $storage"
    cargo build --no-default-features --features "$sphincs $storage"
    if [ $? -ne 0 ]; then
      echo "Build failed for features: $sphincs, $storage"
      exit 1
    fi

    cargo test --no-default-features --features "$sphincs $storage"
    if [ $? -ne 0 ]; then
      echo "Tests failed for features: $sphincs, $storage"
      exit 1
    fi
  done
done

echo "Testing with default features"
cargo build --verbose
if [ $? -ne 0 ]; then
  echo "Build failed for default features"
  exit 1
fi

cargo test --verbose
if [ $? -ne 0 ]; then
  echo "Tests failed for default features"
  exit 1
fi

echo "All combinations built and tested successfully!"