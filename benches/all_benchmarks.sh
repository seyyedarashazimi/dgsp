#!/bin/bash
set -e

sphincs_features=(
  "sphincs_shake_256f"
  "sphincs_shake_256s"
)
storage_types=("memory" "disk")
GROUP_SIZES_LOG=(10 25)
CERTIFICATE_ISSUED_SIZES=(1 8)

update_constants() {
    local group_size_log=$1
    local cert_size=$2

    sed -i "s/const GROUP_SIZE: u64 =.*/const GROUP_SIZE: u64 = 1 << $group_size_log;/" "$BENCHMARK_FILE"
    sed -i "s/const CERTIFICATE_ISSUED_SIZE: usize =.*/const CERTIFICATE_ISSUED_SIZE: usize = $cert_size;/" "$BENCHMARK_FILE"
}

timestamp=$(date +%Y_%m_%d_%H_%M_%S)

for storage in "${storage_types[@]}"; do
  BENCHMARK_FILE="dgsp_full_in_${storage}.rs"
  cp "$BENCHMARK_FILE" "${BENCHMARK_FILE}.bak"
  log_dir="./log_${timestamp}/in_${storage}"
  mkdir -p "$log_dir"

  for group_size_log in "${GROUP_SIZES_LOG[@]}"; do
    for sphincs in "${sphincs_features[@]}"; do
      for cert_size in "${CERTIFICATE_ISSUED_SIZES[@]}"; do
        echo "Running in-${storage} benchmarks for $sphincs, GROUP_SIZE=1<<$group_size_log, CERTIFICATE_ISSUED_SIZE=$cert_size"
        update_constants "$group_size_log" "$cert_size"
        log_file="$log_dir/bench_${sphincs}_group_log_${group_size_log}_cert_${cert_size}.log"
        cargo bench --bench dgsp_full_in_"${storage}" --no-default-features --features "in-${storage} benchmarking ${sphincs}" | tee "${log_file}"
      done
    done
  done

  mv "${BENCHMARK_FILE}.bak" "$BENCHMARK_FILE"
  echo "Benchmarking in-${storage} completed."
done
