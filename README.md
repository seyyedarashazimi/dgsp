# DGSP

[![CI](https://github.com/seyyedarashazimi/dgsp/actions/workflows/rust.yml/badge.svg)](https://github.com/seyyedarashazimi/dgsp/actions/workflows/rust.yml)
[![Docs](https://github.com/seyyedarashazimi/dgsp/actions/workflows/docs.yml/badge.svg)](https://seyyedarashazimi.github.io/dgsp/)
[![crates.io](https://img.shields.io/crates/v/dgsp.svg)](https://crates.io/crates/dgsp)

## Overview

DGSP is an efficient scalable post-quantum fully-dynamic group signature scheme implemented purely in Rust. It leverages the
SPHINCS+ signature scheme to provide a secure, scalable, and efficient group signature mechanism that is
future-proof against quantum adversaries.

DGSP supports:

- A vast user base of up to 2<sup>64</sup> users.
- Compact keypair and signature sizes.
- Efficient signing and verification processes.
- Proven security guarantees for correctness, unforgeability, anonymity, and traceability.
- Manager behavior can be judged.

This implementation is optimized for performance and modularity, making it a powerful choice for cryptographic research
and real-world applications requiring long-term security.

---

## DGSP paper

To obtain more info about DGSP group signature scheme, please refer to the paper at: https://eprint.iacr.org/2025/760

---

## API Documentation

The full API documentation is hosted at: https://seyyedarashazimi.github.io/dgsp/

It is automatically built from the source code.

To build and open the documentation locally from source:

```sh
cargo doc --no-deps --open
```

---

## Features

### Core Functionalities

- **Key Generation**: Manager and user key generation.
- **Joining**: Secure user onboarding via cryptographically generated identifiers.
- **Signing**: Message signing using efficient hash-based cryptographic primitives and pre-computed certificates.
- **Verification**: Signature verification for authenticity and validity.
- **Opening**: Ability to trace signatures to specific users by the manager without compromising anonymity for other parties.
- **Revocation**: Efficient revocation mechanism, including revoking a user, their corresponding signatures, and previously-generated certificates.
- **Judge Manager**: Evaluate manager behavior and make sure manager opens a given signature to an ID correctly.

### Cryptographic Primitives

- **Efficient Hash-Based Cryptographic Operations**:
  - Takes benefit from SHA-2 and SHAKE-based variants as per SPHINCS+ parameters.
- **SPHINCS+ Wrapper**:
  - Simplifies the use of SPHINCS+ by providing utilities for key generation, signing, and verification.
- **WOTS+ (Winternitz One-Time Signature Plus)**:
  - Serves as a base signing primitive for DGSP.
  - Supports unique address derivation to ensure resistance against multi-target attacks.
- **AES**:
  - Plays the role of a strong pseudorandom permutation for traceability.

### Security

- Is built on **SPHINCS+**, a stateless hash-based signature scheme.
- Is resistant to quantum adversaries.
- Provides **user anonymity**, **unforgeability**, **traceability**, and **correctness**.
- Ensures sensitive cryptographic material is securely wiped from memory when no longer needed by zeroizing them.
- Manager's behavior can be audited and judged.

### Scalability and Efficiency

- Handles up to 2<sup>64</sup> users.
- Addition and revocation of new users are seamless and efficient.
- Provides in-memory and in-disk storage backends.
- Parallelized operations using rayon crate for improved performance.
- No setup and initialization time needed.

### Storage Interfaces

- **PLMInterface** (Private List Manager Interface):
  - Stores user-related data such as usernames, activity status, and certificate counters.
  - Provides functionality for adding new users, deactivating users, managing counters for issued certificates, and retrieving user information by ID or username.
  - Supports in-memory and in-disk storage backends for flexibility. 
  - Decouples the DGSP from the storage implementation, enabling integration with other database systems.

- **RevokedListInterface**:
  - Manages the list of revoked certificates and ensures that revoked signatures are invalidated.
  - Supports efficient insertion and checking of revoked certificates using optimized data structures.
  - Designed to work seamlessly with both in-memory and in-disk storage systems.
  - Allows the DGSP to operate independently of the storage implementation, supporting integration with various database systems.

The library itself provides in-memory and in-disk implementations for the above interfaces. However, one can implement these 2 interfaces, corresponding to their own database and needs.

---

## Benchmarks

### DGSP Timing Benchmarks
We ran our tests on a computer with Ubuntu 24.04 using Rust 1.84.0 (stable) in release mode. The tests were done on an
Intel® Core™ i7-4702MQ CPU at 2.20 GHz with 16 GiB of memory. To keep the results steady, we used just one processor 
core and turned off hyper-threading and turbo-boost. The results are the average of 100 test runs. Note that in reality,
the most time-consuming operations like Gen Cert will be run in parallel as the code supports multi-threading.

All benchmark times are in milliseconds (ms).
#### DGSP Timing Benchmarks for `sphincs_shake_256f` feature

```markdown
| DB feature     |             in-memory             |              in-disk              |
| GROUP SIZE     |       2^10      |       2^25      |       2^10      |       2^25      |
| BATCH SIZE     |   1    |   8    |   1    |   8    |   1    |   8    |   1    |   8    |
|----------------|--------|--------|--------|--------|--------|--------|--------|--------|
| Manager KeyGen | 3.0521 | 3.0534 | 3.0536 | 3.0545 | 3.0585 | 3.0594 | 3.0546 | 3.0558 |
| Join           | 0.0030 | 0.0030 | 0.0029 | 0.0029 | 0.0259 | 0.0255 | 0.0278 | 0.0287 |
| CSR            | 1.3630 | 10.985 | 1.3626 | 10.988 | 1.3982 | 11.045 | 1.4025 | 11.051 |
| Gen Cert       | 61.451 | 491.53 | 61.552 | 491.55 | 61.910 | 495.04 | 61.596 | 492.15 |
| Sign           | 1.3875 | 1.3870 | 1.3886 | 1.3869 | 1.4196 | 1.4202 | 1.4186 | 1.4192 |
| Verify         | 2.7706 | 2.7678 | 2.7808 | 2.7725 | 2.7626 | 2.7670 | 2.7667 | 2.7778 |
| Open           | 0.6798 | 0.6948 | 0.6987 | 0.7043 | 0.6957 | 0.6978 | 0.6831 | 0.6954 |
| Judge          | 0.6917 | 0.6912 | 0.7014 | 0.6937 | 0.6914 | 0.6728 | 0.6878 | 0.6877 |
| Revoke         | 0.0007 | 0.0027 | 0.0008 | 0.0027 | 0.0305 | 0.0754 | 0.0259 | 0.0909 |
```

#### DGSP Timing Benchmarks for `sphincs_shake_256s` feature

```markdown
| DB feature     |             in-memory             |              in-disk              |
| GROUP SIZE     |       2^10      |       2^25      |       2^10      |       2^25      |
| BATCH SIZE     |   1    |   8    |   1    |   8    |   1    |   8    |   1    |   8    |
|----------------|--------|--------|--------|--------|--------|--------|--------|--------|
| Manager KeyGen | 48.888 | 48.892 | 48.921 | 48.886 | 48.802 | 48.923 | 48.882 | 48.919 |
| Join           | 0.0030 | 0.0030 | 0.0029 | 0.0029 | 0.0250 | 0.0263 | 0.0272 | 0.0280 |
| CSR            | 1.3552 | 10.894 | 1.3556 | 10.905 | 1.4094 | 11.126 | 1.4117 | 11.137 |
| Gen Cert       | 582.70 | 4661.6 | 583.53 | 4661.6 | 582.93 | 4664.1 | 583.52 | 4667.4 |
| Sign           | 1.3847 | 1.3835 | 1.3863 | 1.3848 | 1.4418 | 1.4396 | 1.4874 | 1.4813 |
| Verify         | 1.8255 | 1.8248 | 1.8207 | 1.8180 | 1.8515 | 1.8561 | 1.8571 | 1.8529 |
| Open           | 0.6991 | 0.6881 | 0.6901 | 0.6911 | 0.7137 | 0.7060 | 0.7197 | 0.7237 |
| Judge          | 0.6806 | 0.6813 | 0.6744 | 0.6798 | 0.7016 | 0.6987 | 0.7016 | 0.6986 |
| Revoke         | 0.0012 | 0.0044 | 0.0012 | 0.0046 | 0.1773 | 0.0733 | 0.0322 | 0.0797 |
```

### DGSP Size of Manager Keys and Signature
All sizes are in Bytes.

```markdown
| SPHINCS+ feature   | Public Key | Secret Key | Signature |
|--------------------|------------|------------|-----------|
| sphincs_sha2_128f  |     32     |     96     |   17696   |
| sphincs_sha2_128s  |     32     |     96     |    8464   |
| sphincs_sha2_192f  |     48     |    144     |   36952   |
| sphincs_sha2_192s  |     48     |    144     |   17512   |
| sphincs_sha2_256f  |     64     |    192     |   52080   |
| sphincs_sha2_256s  |     64     |    192     |   32016   |
| sphincs_shake_128f |     32     |     96     |   17696   |
| sphincs_shake_128s |     32     |     96     |    8464   |
| sphincs_shake_192f |     48     |    144     |   36952   |
| sphincs_shake_192s |     48     |    144     |   17512   |
| sphincs_shake_256f |     64     |    192     |   52080   |
| sphincs_shake_256s |     64     |    192     |   32016   |
```

---

## Installation

### Prerequisites

DGSP is fully implemented in Rust. Install Rust via [rustup](https://rustup.rs/).

- **Minimum Supported Rust Version (MSRV):** 1.63.0
- **Rust version used for the benchmarks in this README:** 1.84.0 (stable)
- **Platform used for benchmarks:** Ubuntu 24.04, Intel® Core™ i7-4702MQ @ 2.20 GHz, 16 GiB RAM

### Dependencies

The following table lists all direct dependencies and the versions used:

| Dependency             | Version | Notes                                                      |
|:-----------------------|:--------|:-----------------------------------------------------------|
| `aes`                  | 0.8.4   | AES block cipher for traceability                          |
| `pqcrypto-sphincsplus` | 0.7.0   | SPHINCS+ signature scheme                                  |
| `pqcrypto-traits`      | 0.3.5   | Traits for pqcrypto crates                                 |
| `rand`                 | 0.8.5   | Random number generation                                   |
| `rayon`                | 1.10.0  | Data parallelism                                           |
| `thiserror`            | 2.0.11  | Error type derivation                                      |
| `zeroize`              | 1.8.1   | Secure memory wiping                                       |
| `bincode`              | 1.3.3   | Binary serialization (optional, `in-disk`)                 |
| `serde`                | 1.0     | Serialization framework (optional, `serialization`)        |
| `serde_json`           | 1.0     | JSON serialization (optional, `in-disk`)                   |
| `serde-big-array`      | 0.5.1   | Serde support for large arrays (optional, `serialization`) |
| `sha2`                 | 0.10.8  | SHA-2 hash functions (optional, `sphincs_sha2_*`)          |
| `sha3`                 | 0.10.8  | SHA-3/SHAKE hash functions (optional, `sphincs_shake_*`)   |
| `sled`                 | 0.34.7  | Embedded database (optional, `in-disk`)                    |

Dev dependencies: `criterion` 0.5 (benchmarking), `tempfile` 3.15 (tests), `tracing-test` 0.2.5 (tests).

### Docker (alternative to a local Rust installation)

A pre-built Docker image is available on Docker Hub and provides a fully self-contained environment with Rust 1.84.0 and all dependencies already compiled:

```bash
docker pull arashazimi/dgsp
```

Run the end-to-end example:
```bash
docker run --rm arashazimi/dgsp cargo run --example simple --release
```

Run the full test suite:
```bash
docker run --rm arashazimi/dgsp cargo test --release
```

Run a benchmark (e.g. in-memory, `sphincs_shake_256f`):
```bash
docker run --rm arashazimi/dgsp \
    cargo bench --bench dgsp_full_in_memory \
    --no-default-features --features "in-memory benchmarking sphincs_shake_256f"
```

Reproduce all paper benchmark configurations:
```bash
docker run --rm arashazimi/dgsp bash benches/all_benchmarks.sh
```

To build the image locally from source:
```bash
docker build -t arashazimi/dgsp .
```

### Add DGSP to Your Project

To use DGSP as a library, add it to your `Cargo.toml`:

```toml
[dependencies]
dgsp = "0.1.0"
```

To enable specific features during installation, use as an example:
```toml
[dependencies]
dgsp = { version = "0.1.0", default-features = false, features = ["in-disk", "sphincs_shake_256f"] }
```

---

## Basic Usage

### Manager Setup

Generate manager keys, and open private list of the manager and public revoked list databases:

```rust,ignore
use dgsp::*;

// generate manager keypairs:
let (pkm, skm) = DGSP::keygen_manager().unwrap();

// generate plm and revoked_list using in-memory feature
let plm = InMemoryPLM::open("").unwrap();
let revoked_list = InMemoryRevokedList::open("").unwrap();

// or generate plm and revoked_list using in-disk feature
use std::path::PathBuf;
let path = PathBuf::new();
let plm = InDiskPLM::open(&path).unwrap();
let revoked_list = InDiskRevokedList::open(&path).unwrap();
```

### User Setup

A user joins the system and obtains their unique ID and cryptographic identifier:

```rust,ignore
let username = "alice";
let (id, cid_star) = DGSP::join(&skm.msk.hash_secret, username, &plm).unwrap();
```

The user also generate a private seed:

```rust,ignore
let seed_u = DGSP::keygen_user();
```

### CSR, Certificate, and Signing

Create a batch of certificate signing request:

```rust,ignore
let batch_size = 8;
let (wots_pks, mut wots_seeds) = DGSP::csr(&seed_u, batch_size);
```

Manager generates the corresponding certificates:
```rust,ignore
let mut certs = DGSP::gen_cert(&skm, id, &cid_star, &wots_pks, &plm).unwrap();
```

User signs a message:
```rust,ignore
let message = b"Hello, DGSP!";
let signature = DGSP::sign(message, &seed_u, id, &cid_star, wots_seeds.pop().unwrap(), certs.pop().unwrap());
```

### Verifying

Verify the signature:
```rust,ignore
DGSP::verify(message, &signature, &revoked_list, &pkm).unwrap();
```

### Opening

Manager can open a signature to find out who has signed it:
```rust,ignore
let (signer_id, signer_username, proof) = DGSP::open(&skm.msk, &plm, &signature, message).unwrap();
```

### Judging

Judge manager to make sure the given signature and message are correctly opened to the user id:
```rust,ignore
DGSP::judge(&signature, message, id, &proof).unwrap();
```

### Revocation

Revoke a user and their associated certificates:
```rust,ignore
DGSP::revoke(&skm.msk.aes_key, &plm, &[id], &revoked_list).unwrap();
```

To learn more, refer to the `examples/simple.rs` for additional information. One can run the `simple.rs` example for a specific sphincs feature via:
```bash
cargo run --example simple --no-default-features --features "in-disk in-memory sphincs_shake_256f" --release
```

---

## Testing

Run tests using:

```sh
cargo test
```

To test specific configurations, enable the required feature flags:

```sh
cargo test --no-default-features --features "in-disk sphincs_shake_256f"
```

To test all combination of configurations in Unix-like operating systems, run the provided script: 
```bash
bash ./tests/all_features_full_test.sh
```

Note that the full test will take some time to complete.

---

## Benchmarks

Run benchmarks using:

```sh
cargo bench --bench dgsp_full_in_disk
cargo bench --bench dgsp_full_in_memory
```

Note that the above will run the benchmarks for the default features selected in Cargo.toml. To choose a specific SPHINCS+ feature, run: 

```sh
cargo bench --bench dgsp_full_in_disk --no-default-features --features "in-disk benchmarking sphincs_shake_256s"
cargo bench --bench dgsp_full_in_memory --no-default-features --features "in-memory benchmarking sphincs_shake_256s"
```

### Reproducing the Paper's Benchmark Tables

To reproduce the full set of timing benchmarks reported in the paper, use the provided script that iterates over all configurations
(two selected SPHINCS+ variants × both storage backends × group sizes 2^10 and 2^25 × batch sizes 1 and 8):

```bash
cd benches
bash all_benchmarks.sh
```

The script modifies the benchmark constants, runs Criterion for each configuration, and saves raw logs under
`benches/log_<timestamp>/in_memory/` and `benches/log_<timestamp>/in_disk/`.

> **Note:** The 2^25 configurations require significant RAM (in-memory) and disk space (in-disk). Remove `25` from `GROUP_SIZES_LOG` in `all_benchmarks.sh` if resources are limited.

**Reading the output:** Each Criterion block looks like:

```
DGSP_in_memory_using_sphincs_shake_256f_with_1024_users_and_1_batch/keygen_manager
                        time:   [3.0519 ms 3.0521 ms 3.0524 ms]
```

The three values are the lower confidence bound, **mean**, and upper confidence bound over 100 samples. 
The paper reports the **mean** (middle value).
To populate the paper's table, collect the mean for each operation (`keygen_manager`, `join`, `csr`, `gen_cert`, `sign`, `verify`, `open`, `judge`, `revoke`) from the corresponding log file and convert to milliseconds if needed (Criterion prints in `s`, `ms`, `µs`, or `ns` depending on magnitude).

> **Note:** The benchmarks were obtained on a specific machine (Ubuntu 24.04, Intel® Core™ i7-4702MQ @ 2.20 GHz, single core, hyper-threading and turbo-boost disabled). Results on other hardware will differ in absolute values, but the relative ordering and scaling behavior should support the main claims of the paper.

---

## Feature Flags

The library supports several feature flags for customization:

- **`in-disk`**: Enables in-disk storage using `sled` crate.
- **`in-memory`**: Enables in-memory storage.
- **`serialization`**: Enables serialization of cryptographic keys and structures.
- **SPHINCS+ Variants**: Choose from SHA-2-based or SHAKE-based configurations with varying security levels and performance/size goals: 
  - `sphincs_sha2_128f`
  - `sphincs_sha2_128s`
  - `sphincs_sha2_192f`
  - `sphincs_sha2_192s`
  - `sphincs_sha2_256f`
  - `sphincs_sha2_256s`
  - `sphincs_shake_128f`
  - `sphincs_shake_128s`
  - `sphincs_shake_192f`
  - `sphincs_shake_192s`
  - `sphincs_shake_256f`
  - `sphincs_shake_256s`
- **`benchmarking`**: Used for benchmarking purposes.

[//]: # (_default features:_ `in-disk`, `in-memory`, `serialization`, `sphincs_shake_256f`, `benchmarking` )

---

## Source Code Organization

```
src/
├── lib.rs              # Crate root; re-exports the public API
├── scheme.rs           # Core protocol: all DGSP algorithms (keygen_manager, keygen_user,
│                       #   join, csr, gen_cert, sign, verify, open, judge, revoke) and all
│                       #   key / signature / certificate type definitions
├── params.rs           # Compile-time constants derived from the chosen SPHINCS+ variant
│                       #   (security level λ, byte sizes for keys, signatures, etc.)
├── db.rs               # PLMInterface and RevokedListInterface trait definitions
├── db/
│   ├── in_memory.rs    # In-memory PLM and RevokedList (feature: in-memory)
│   └── in_disk.rs      # Persistent sled-backed PLM and RevokedList (feature: in-disk)
├── cipher.rs           # AES wrapper used for user-ID encryption in traceability
├── hash.rs             # Hash function dispatcher (SHA-2 or SHAKE, selected at compile time)
├── hash/               # Per-parameter-set SHA-2 and SHAKE implementations
├── sphincs_plus.rs     # SPHINCS+ wrapper: key generation, signing, verification
├── sphincs_plus/       # Per-parameter-set SPHINCS+ constants and ADRS byte-offset tables
├── wots_plus.rs        # WOTS+ (Winternitz One-Time Signature Plus) core implementation
├── wots_plus/          # ADRS (address) type used by WOTS+ operations
├── error.rs            # Error and Result types (Error, VerificationError)
└── utils.rs            # Internal byte-conversion helpers (u32/u64 ↔ big-endian bytes)

benches/
├── dgsp_full_in_memory.rs   # Criterion benchmark suite for the in-memory backend
├── dgsp_full_in_disk.rs     # Criterion benchmark suite for the in-disk backend
├── bench_utils.rs           # Shared helpers (SPHINCS+ feature detection, duration formatting)
└── all_benchmarks.sh        # Runs all benchmark configurations and collects log files

examples/
└── simple.rs           # End-to-end example covering all DGSP operations

tests/
└── all_features_full_test.sh  # Iterates over all SPHINCS+ × storage feature combinations
                               #   and runs the full test suite for each
```

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.

---

## License

This repository is licensed under the [MIT License](https://github.com/seyyedarashazimi/dgsp/blob/main/LICENSE).

