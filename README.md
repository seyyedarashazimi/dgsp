# DGSP

## Overview

DGSP is an efficient scalable post-quantum fully-dynamic group signature scheme implemented purely in Rust. It leverages the
SPHINCS+ signature scheme to provide a secure, scalable, and efficient group signature mechanism that is
future-proof against quantum adversaries.

DGSP supports:

- A vast user base of up to 2<sup>64</sup> users.
- Compact keypair and signature sizes.
- Efficient signing and verification processes.
- Proven security guarantees for correctness, unforgeability, anonymity, and traceability.

This implementation is optimized for performance and modularity, making it a powerful choice for cryptographic research
and real-world applications requiring long-term security.

---

## DGSP paper

To obtain more info about DGSP group signature scheme, please refer to:

> PAPER CITE.

Find the paper at https://eprint.iacr.org/2025/XXXX

Please cite this work when referring to DGSP:
```bibtex
bibtex cite
```

[//]: # (```bibtex)

[//]: # (@inproceedings{SSR:KSSW22,)

[//]: # (  author    = {Matthias J. Kannwischer and)

[//]: # (               Peter Schwabe and)

[//]: # (               Douglas Stebila and)

[//]: # (               Thom Wiggers},)

[//]: # (  title     = {Improving Software Quality in Cryptography Standardization Projects},)

[//]: # (  booktitle = {{IEEE} European Symposium on Security and Privacy, EuroS{\&}P 2022 - Workshops, Genoa, Italy, June 6-10, 2022},)

[//]: # (  pages     = {19--30},)

[//]: # (  publisher = {IEEE Computer Society},)

[//]: # (  address   = {Los Alamitos, CA, USA},)

[//]: # (  year      = {2022},)

[//]: # (  url       = {https://eprint.iacr.org/2022/337},)

[//]: # (  doi       = {10.1109/EuroSPW55150.2022.00010},)

[//]: # (})

[//]: # (```)

---

## Features

### Core Functionalities

- **Key Generation**: Manager and user key generation.
- **Joining**: Secure user onboarding via cryptographically generated identifiers.
- **Signing**: Message signing using efficient hash-based cryptographic primitives and pre-computed certificates.
- **Verification**: Signature verification for authenticity and validity.
- **Opening**: Ability to trace signatures to specific users by the manager without compromising anonymity for other parties.
- **Revocation**: Efficient revocation mechanism, including revoking a user, their corresponding signatures, and previously-generated certificates.

### Cryptographic Primitives

- **Efficient Hash-Based Cryptographic Operations**:
  - Takes benefit from SHA-2 and SHAKE-based variants as per SPHINCS+ parameters.
- **SPHINCS+ Wrapper**:
  - Simplifies the use of SPHINCS+ by providing utilities for key generation, signing, and verification.
- **WOTS+ (Winternitz One-Time Signature Plus)**:
  - Serves as a base signing primitive for DGSP.
  - Supports unique address derivation to ensure resistance against multi-target attacks.
- **AES-256**:
  - Plays the role of a strong pseudorandom permutation for traceability.

### Security

- Is built on **SPHINCS+**, a stateless hash-based signature scheme.
- Is resistant to quantum adversaries.
- Provides **user anonymity**, **unforgeability**, **traceability**, and **correctness**.
- Ensures sensitive cryptographic material is securely wiped from memory when no longer needed by zeroizing them.

### Scalability and Efficiency

- Handles up to 2<sup>64</sup> users.
- Addition and revocation of new users are seamless and efficient.
- Provides in-memory and in-disk storage backends.
- Parallelized operations using rayon crate for improved performance.

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

## Installation

### Prerequisites

DGSP is fully implemented in Rust. 
Install Rust (version>=1.63.0) via [rustup](https://rustup.rs/).

### Add DGSP to Your Project

To use DGSP as a library, add it to your `Cargo.toml`:

```toml
[dependencies]
dgsp = { path = "path/to/dgsp" }
```

Alternatively, if published to crates.io:

```toml
[dependencies]
dgsp = "0.1.0"
```

To enable specific features during installation, use as an example:
```toml
[dependencies]
dgsp = { version = "0.1.0", default-features = false, features = ["in-disk", "sphincs_sha2_256f"] }
```

---

## Basic Usage

### Manager Setup

Generate manager keys, and open private list of the manager and public revoked list databases:

```rust,ignore
use dgsp::dgsp::DGSP;
use dgsp::{InMemoryPLM, InMemoryRevokedList};
use dgsp::{InDiskPLM, InDiskRevokedList};
use std::path::PathBuf;

// generate manager keypairs:
let (pkm, skm) = DGSP::keygen_manager().unwrap();

// generate plm and revoked_list using in-memory feature
let plm = InMemoryPLM::open("").unwrap();
let revoked_list = InMemoryRevokedList::open("").unwrap();

// or generate plm and revoked_list using in-disk feature
let path = PathBuf::new();
let plm = InMemoryPLM::open(&path).unwrap();
let revoked_list = InMemoryRevokedList::open(&path).unwrap();
```

### User Setup

A user joins the system and obtains their unique ID and cryptographic identifier:

```rust,ignore
let username = "alice";
let (id, cid) = DGSP::join(&skm.msk, username, &plm).unwrap();
```

The user also generate a private seed:

```rust,ignore
let seed_u = DGSP::keygen_user();
```

### CSR, Certificate, and Signing

Create a batch of certificate signing request:

```rust,ignore
let batch_size = 8;
let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, batch_size);
```

Manager generates the corresponding certificates:
```rust,ignore
let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
```

User signs a message:

```rust,ignore
let message = b"Hello, DGSP!";
let signature = DGSP::sign(&message, wots_rands.pop.unwrap(), &seed_u, certs.pop.unwrap());
```

### Verifying

Verify the signature:

```rust,ignore
DGSP::verify(&message, &signature, &revoked_list, &pkm).unwrap();
```

### Opening

Manager can open a signature to find out who has signed it:

```rust,ignore
let (signer_id, signer_username) = DGSP::open(&skm.msk, &plm, &signature).unwrap();
```

### Revocation

Revoke a user and their associated certificates:

```rust,ignore
DGSP::revoke(&skm.msk, &plm, vec![id], &revoked_list).unwrap();
```

To learn more, refer to the `examples/simple.rs` for additional information. One can run the `simple.rs` example for a specific sphincs feature via:

```bash
cargo run --example simple --no-default-features --features "in-disk in-memory sphincs_shake_192f" --release
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

Note that the full test may take some time to complete.

---

## Benchmarks

Run benchmarks using:

```sh
cargo bench --bench dgsp_full_in_disk
cargo bench --bench dgsp_full_in_memory
```

Note that the above will run the benchmarks for the default features selected in Cargo.toml. To choose a specific SPHINCS+ feature, run: 

```sh
cargo bench --bench dgsp_full_in_disk --no-default-features --features "in-disk benchmarking <SPHINCS+_FEATURE>"
cargo bench --bench dgsp_full_in_memory --no-default-features --features "in-memory benchmarking <SPHINCS+_FEATURE>"
```
where `<SPHINCS+_FEATURE>` represents the specific SPHINCS+ feature for which the benchmark will be executed, such as `sphincs_sha2_256s` or `sphincs_shake_128f`.

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

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.

---

## Minimum Supported Rust Version (MSRV)

This crate requires **Rust 1.63** or higher.

---

## License

This repository is licensed under the [MIT License](https://github.com/seyyedarashazimi/dgsp/blob/main/LICENSE).

