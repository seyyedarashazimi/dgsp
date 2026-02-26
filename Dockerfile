# DGSP – Artifact Docker Image
#
# Provides a reproducible environment to build, test, and benchmark the DGSP
# crate without installing Rust locally.
#
# --- Build locally ---
#   docker build -t arashazimi/dgsp .
#
# --- Or pull the pre-built image from Docker Hub ---
#   docker pull arashazimi/dgsp
#
# --- Run the end-to-end example (default features) ---
#   docker run --rm arashazimi/dgsp cargo run --example simple --release
#
# --- Run the full test suite (default features) ---
#   docker run --rm arashazimi/dgsp cargo test --release
#
# --- Run the full test suite across all feature combinations ---
#   docker run --rm arashazimi/dgsp bash tests/all_features_full_test.sh
#
# --- Run tests for a specific feature combination ---
#   docker run --rm arashazimi/dgsp \
#       cargo test --no-default-features \
#       --features "in-memory sphincs_shake_256f" --release
#
# --- Run a single benchmark configuration ---
#   docker run --rm arashazimi/dgsp \
#       cargo bench --bench dgsp_full_in_memory \
#       --no-default-features \
#       --features "in-memory benchmarking sphincs_shake_256f"
#
# --- Reproduce all paper benchmark configurations (Section 5, Tables 6 and 7) ---
#   docker run --rm arashazimi/dgsp bash benches/all_benchmarks.sh

FROM rust:1.84.0-slim-bookworm

WORKDIR /dgsp
COPY . .

RUN cargo build --release
RUN cargo test --release

CMD ["cargo", "run", "--example", "simple", "--release"]
