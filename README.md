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
- Manager behavior can be checked and judged.

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
- **Check Manager**: Evaluate manager behavior and make sure manager creates certificates and opens a given signature to an ID correctly.

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
- Does not assume a trusted manager as manager can be audited as well.

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
| Manager KeyGen | 3.0538 | 3.0526 | 3.0530 | 3.0517 | 3.0578 | 3.0524 | 3.0552 | 3.0551 |
| Join           | 0.0019 | 0.0019 | 0.0017 | 0.0017 | 0.0241 | 0.0240 | 0.0276 | 0.0297 |
| CSR            | 1.3623 | 11.013 | 1.3613 | 11.019 | 1.3743 | 11.082 | 1.3655 | 11.001 |
| Gen Cert       | 61.507 | 491.51 | 61.472 | 493.58 | 62.093 | 491.57 | 61.568 | 492.53 |
| Check Cert     | 2.0900 | 16.734 | 2.0920 | 16.722 | 2.0913 | 16.727 | 2.0918 | 16.703 |
| Sign           | 1.4114 | 1.4129 | 1.4119 | 1.4127 | 1.4043 | 1.4014 | 1.3900 | 1.3906 |
| Verify         | 2.7698 | 2.7768 | 2.7697 | 2.7681 | 2.7593 | 2.7695 | 2.7662 | 2.7611 |
| Open           | 0.6865 | 0.6857 | 0.6941 | 0.6906 | 0.6923 | 0.6831 | 0.6816 | 0.6696 |
| Judge          | 0.6848 | 0.6934 | 0.6923 | 0.6901 | 0.6722 | 0.6859 | 0.6782 | 0.6741 |
| Revoke         | 0.0006 | 0.0023 | 0.0007 | 0.0022 | 0.0251 | 0.0572 | 0.0278 | 0.0678 |
```

#### DGSP Timing Benchmarks for `sphincs_shake_256s` feature

```markdown
| DB feature     |             in-memory             |              in-disk              |
| GROUP SIZE     |       2^10      |       2^25      |       2^10      |       2^25      |
| BATCH SIZE     |   1    |   8    |   1    |   8    |   1    |   8    |   1    |   8    |
|----------------|--------|--------|--------|--------|--------|--------|--------|--------|
| Manager KeyGen | 48.880 | 48.778 | 48.786 | 48.837 | 48.803 | 48.816 | 48.916 | 48.830 |
| Join           | 0.0019 | 0.0019 | 0.0017 | 0.0017 | 0.0246 | 0.0243 | 0.0270 | 0.0263 |
| CSR            | 1.3498 | 10.926 | 1.3493 | 10.916 | 1.3476 | 10.900 | 1.3590 | 10.990 |
| Gen Cert       | 581.79 | 4656.2 | 581.89 | 4655.2 | 581.91 | 4666.7 | 583.47 | 4661.4 |
| Check Cert     | 1.1426 | 9.1171 | 1.1405 | 9.1137 | 1.1419 | 9.1060 | 1.1517 | 9.1636 |
| Sign           | 1.3932 | 1.3932 | 1.3933 | 1.3922 | 1.3727 | 1.3719 | 1.4277 | 1.4283 |
| Verify         | 1.8276 | 1.8168 | 1.8152 | 1.8259 | 1.8003 | 1.7993 | 1.8305 | 1.8206 |
| Open           | 0.6984 | 0.6962 | 0.7045 | 0.6972 | 0.6738 | 0.6648 | 0.6832 | 0.6793 |
| Judge          | 0.6777 | 0.6801 | 0.6840 | 0.6785 | 0.6659 | 0.6567 | 0.6745 | 0.6720 |
| Revoke         | 0.0009 | 0.0029 | 0.0008 | 0.0028 | 0.0399 | 0.0674 | 0.0311 | 0.0745 |
```

### DGSP Size of Manager Keys and Signature
All sizes are in Bytes.

```markdown
| SPHINCS+ feature   | Public Key | Secret Key | Signature |
|--------------------|------------|------------|-----------|
| sphincs_sha2_128f  |     32     |     80     |   17704   |
| sphincs_sha2_128s  |     32     |     80     |    8472   |
| sphincs_sha2_192f  |     48     |    120     |   36960   |
| sphincs_sha2_192s  |     48     |    120     |   17520   |
| sphincs_sha2_256f  |     64     |    160     |   52088   |
| sphincs_sha2_256s  |     64     |    160     |   32024   |
| sphincs_shake_128f |     32     |     80     |   17704   |
| sphincs_shake_128s |     32     |     80     |    8472   |
| sphincs_shake_192f |     48     |    120     |   36960   |
| sphincs_shake_192s |     48     |    120     |   17520   |
| sphincs_shake_256f |     64     |    160     |   52088   |
| sphincs_shake_256s |     64     |    160     |   32024   |
```

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
dgsp = { version = "0.1.0", default-features = false, features = ["in-disk", "sphincs_shake_256f"] }
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
let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, batch_size);
```

Manager generates the corresponding certificates:
```rust,ignore
let mut certs = DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
```

User can check if given certificates are correct or not:
```rust,ignore
DGSP::check_cert(id, &cid, &wots_pks, &certs, &pkm).unwrap();
```

User signs a message:
```rust,ignore
let message = b"Hello, DGSP!".as_bytes();
let signature = DGSP::sign(message, &seed_u, id, &cid, wots_rands.pop.unwrap(), certs.pop.unwrap());
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
DGSP::revoke(&skm.msk, &plm, &[id], &revoked_list).unwrap()
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

