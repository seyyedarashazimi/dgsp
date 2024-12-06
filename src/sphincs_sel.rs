//! # Selenite: A Core Crypto Module
//!
//! Lacuna's Core Crypto Module consists of the structs of keypairs (FALCON512,FALCON1024,SPHINCS+), the signature struct, and most importantly the implemented traits.
//!
//! When viewing documentation for a struct, make sure to look at the documentation for the traits **Keypairs** and **Signatures** as these contain the implemented methods.
//!
//! ## Security Warning
//!
//! This code **is not** audited and just recomended for **educational purposes**. Feel free to look through the code and help me out with it as the code is a bit... rusty.
//!
//! ## Example Usage
//!
//! ```
// use selenite::crypto::*;
//
// fn main() {
//     // Generates The Respected Keypair
//     let keypair = SphincsKeypair::new();
//
//     // Signs The Message as a UTF-8 Encoded String
//     let mut sig = keypair.sign("message_to_sign");
//
//     // Returns a boolean representing whether the signature is valid or not
//     let is_verified = sig.verify();
// }
//! ```
//! ## How To Use
//!
//! This is based upon my beliefs. You may choose yourself.
//!
//! **SPHINCS+** should be used for code signing as it is quite slow at signing/verifying but is based on some high security assumptions and has a high security bit level.
//!
//! **FALCON512/FALCON1024** is comparable to **RSA2048/RSA4096** and is fast at signing/verifying. It produces much smaller signatures but has a larger public key size (but still quite small).
//!
//!
//! ## Serialization
//!
//! Serde-yaml is implemented by default for the serialization/deserialization of the data to the human-readable .yaml format.
//!
//! ## More Information
//!
//! This library is built on bindings to **pqcrypto**, a portable, post-quantum, cryptographic library.
//!
//! SPHINCS+ reaches a security bit level of **255 bytes** which is well over what is needed and is **Level 5**. I have plans in the future to reduce this so the signature size is smaller.
//!
//! ## References
//!
//! [pqcrypto-rust](https://github.com/rustpq/pqcrypto)
//!
//! [SPHINCS+](https://sphincs.org/)
//!
//! [SPHINCS+ REPO](https://github.com/sphincs/sphincsplus)
//!
//! [Falcon-Sign](https://falcon-sign.info/)

// Errors
use std::path::Path;
use blake2_rfc::blake2b::{blake2b, Blake2bResult};

// Serialization
use serde::{Serialize, Deserialize};

// PQcrypto Digital Signatures
use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature,VerificationError};
use pqcrypto_sphincsplus::sphincsshake256fsimple;

extern crate rand;

pub use zeroize::Zeroize;

use crate::errors::SeleniteErrors;

//===INFORMATION===
// All Serialization can be done through YAML
// Serialization For Signatures can be done through bincode

// [Keypair Structs]
// All Keypair Structs come with three fields all being strings
// - algorithm {FALCON512,FALCON1024,SPHINCS+}
// - public_key
// - private_key

// - Public Keys and Private Keys are encoded in hexadecimal;
// - The Signature of the Signatures struct is encoded in base64

//TODO
// - Fix bincode serialization parameter

//=============================================================================================================================
/// # Algorithms
/// This enum lists the algorithms implemented in the crate.
/// - `SphincsPlus` uses SPHINCS+ (SHAKE256) (256s) (Robust). The algorithm itself is highly secure and reaches Level 5.
pub enum KeypairAlgorithms {
    FALCON512,
    FALCON1024,
    SphincsPlus,
    ED25519,
    BLS,
}

pub enum SignatureType {
    String,
    Bytes,
}
/// # Traits For Keypairs
///
/// These traits are required to access the methods of the Keypair Structs. They implement basic functionality like conversion from hexadecimal to bytes, serializing/deserializing content, and signing inputs.
pub trait Keypairs {
    /// ## Algorithm
    /// Shows the Algorithm For The Keypair Being Used
    const ALGORITHM: &'static str;
    /// ## Version
    /// Returns The Version. 0 for unstable test. 1 for first implementation.
    const VERSION: usize;
    const PUBLIC_KEY_SIZE: usize;
    const SECRET_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;


    /// ## Generate A New Keypair
    /// Creates A New Keypair From Respected Struct Being Called.
    ///
    /// Keypair Options:
    /// - FALCON512
    /// - FALCON1024
    /// - SPHINCS+
    fn new() -> Self;
    /// ## Serializes To YAML
    /// This will serialize the contents of the keypair to YAML Format, which can be read with the import function.
    fn serialize(&self) -> String;
    /// ## Construct Keypair From YAML
    /// This function will deserialize the keypair into its respected struct.
    fn deserialize(yaml: &str) -> Self;
    /// Return As Bytes
    fn public_key_as_bytes(&self) -> Vec<u8>;
    fn secret_key_as_bytes(&self) -> Vec<u8>;

    fn return_public_key_as_hex(&self) -> String;
    fn return_secret_key_as_hex(&self) -> String;

    fn decode_from_hex(s: String) -> Result<Vec<u8>,SeleniteErrors>;
    /// ## Keypair Signing
    /// Allows Signing of an Input Using The Keyholder's Secret Key and Returns The Struct Signature.
    fn sign(&self,message: &str) -> Signature;

    /// ## Sign (with Hash)
    ///
    /// Signing bytes using `sign_data()` with Hash takes as input a slice of bytes. It then signs the hash of the bytes as opposed to signing the actual bytes.
    fn sign_data<T: AsRef<[u8]>>(&self, data: T) -> Signature;

    /// ## Sign File
    ///
    /// This method lets you sign a file by signing the file's hash.
    fn sign_file<T: AsRef<Path>>(&self, path: T) -> Result<Signature,SeleniteErrors>;

    /// ## Data as Hexadecimal Hash
    ///
    /// This function takes the data as a vector of bytes
    fn data_as_hexadecimal_hash(data: &[u8]) -> String;
    /// ## Data as Hash (in bytes)
    ///
    /// This function returns the hash of the data as a vector of bytes
    fn data_as_hash(data: &[u8]) -> Vec<u8>;

    /// ## From
    ///
    /// Converts from hexadecimal public key + private key to the respected struct. Also requires the algorithm to be known.
    fn construct_from<T: AsRef<str>>(pk: T, sk: T) -> Self;
}
/// # Traits For Signatures
///
/// These traits are required for properly handling signatures. They allow the serialization/deserialization of signatures, the conversion into bytes, and the verification of signatures.
pub trait Signatures {
    fn new(algorithm: &str, pk: &str, signature: &str, message: &str) -> Self;
    // bincode implementations
    fn serialize_to_bincode(&self) -> Vec<u8>;
    // TODO: Think about changing the type to &[u8] for import
    fn deserialize_from_bincode(serde_bincode: Vec<u8>) -> Self;
    /// Serializes To YAML
    fn serialize(&self) -> String;
    /// Deserializes From YAML
    fn deserialize(yaml: &str) -> Self;
    /// Verifies a Signature
    fn verify(&self) -> bool;
    fn signature_as_bytes(&self) -> Vec<u8>;
    fn message_as_bytes(&self) -> &[u8];
    /// # [Security] Compare Public Key
    /// This will match the public key in the struct to another public key you provide to make sure they are the same. The Public Key **must** be in **upperhexadecimal format**.
    fn compare_public_key(&self, pk: String) -> bool;
    /// # [Security] Compare Message
    /// This will match the message in the struct to the message you provide to make sure they are the same.
    fn compare_message(&self,msg: String) -> bool;
    /// # [Security] Matches Signatures
    /// This will match the signature in the struct with a provided signature (in base64 format)
    fn compare_signature(&self,signature: String) -> bool;
}

pub struct BLSAggregatedSignature {
    pk: Vec<String>,
    messages: Vec<String>,
    signature: String,
}

/// ## SPHINCS+ (SHAKE256) Keypair
///
/// When using this keypair or looking at its documentation, please look at its implemented trait **Keypairs** for its methods.
///
/// ```
// use selenite::crypto::*;
//
// fn main() {
//     // Generates The Respected Keypair
//     let keypair = SphincsKeypair::new();
//
//     // Signs The Message as a UTF-8 Encoded String
//     let mut sig = keypair.sign_str("message_to_sign");
//
//     // Returns a boolean representing whether the signature is valid or not
//     let is_verified = sig.verify();
// }
/// ```
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct SphincsKeypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
}
/// ## ED25519 Keypair
///
/// ED25519 is an elliptic-curve based digital signature scheme that is used for signing messages securely.
///
/// It is not post-quantum cryptography but due to its small keypair/signatures and speed, it has been included in the library.
///
/// ```
// use selenite::crypto::*;
//
// fn main() {
//     let keypair = ED25519::new();
//
//     let signature = keypair.sign_str("This message is being signed.");
//
//     let is_valid = signature.verify();
//
//     assert!(is_valid);
//
// }
/// ```
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default,Zeroize)]
#[zeroize(drop)]
pub struct ED25519Keypair {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// ## BLS Curve
/// ### Description
///
/// The BLS Curve is an elliptic curve based crypto that is not post-quantum cryptography but provides **signature aggregation** that is useful in many applications.
/// ### Developer Notes
///
/// Instead of storing itself in a Hexadecimal String, the private key and public key is stored as a byte array
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default,Zeroize)]
#[zeroize(drop)]
pub struct BLSKeypair {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// ## Falcon1024 Keypair
///
/// When using this keypair or looking at its documentation, please look at its implemented trait **Keypairs** for its methods.
///
/// ```
// use selenite::crypto::*;
//
// fn main() {
//     // Generates The Respected Keypair
//     let keypair = Falcon1024Keypair::new();
//
//     // Signs The Message as a UTF-8 Encoded String
//     let mut sig = keypair.sign("message_to_sign");
//
//     // Returns a boolean representing whether the signature is valid or not
//     let is_verified = sig.verify();
// }
/// ```
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default,Zeroize)]
#[zeroize(drop)]
pub struct Falcon1024Keypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
}
/// ## Falcon512 Keypair
///
/// When using this keypair or looking at its documentation, please look at its implemented trait **Keypairs** for its methods.
///
/// ```
// use selenite::crypto::*;
//
// fn main() {
//     // Generates The Respected Keypair
//     let keypair = Falcon512Keypair::new();
//
//     // Signs The Message as a UTF-8 Encoded String
//     let mut sig = keypair.sign("message_to_sign");
//
//     // Returns a boolean representing whether the signature is valid or not
//     let is_verified = sig.verify();
// }
/// ```
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default,Zeroize)]
#[zeroize(drop)]
pub struct Falcon512Keypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
}
/// ## The Signature Struct
///
/// This struct contains the fields for signatures and implements the Signatures trait to allow methods on the struct.
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default,Zeroize)]
#[zeroize(drop)]
pub struct Signature {
    pub algorithm: String,
    pub public_key: String,
    pub message: String,
    pub signature: String,

    pub is_str: bool,
}

pub struct Verify;

impl Keypairs for SphincsKeypair {
    const VERSION: usize = 0;
    const ALGORITHM: &'static str = "SPHINCS+";
    const PUBLIC_KEY_SIZE: usize = 64;
    const SECRET_KEY_SIZE: usize = 128;
    const SIGNATURE_SIZE: usize = 29_792;

    fn new() -> Self {
        let (pk,sk) = sphincsshake256fsimple::keypair();
        //let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        SphincsKeypair {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(pk.as_bytes()),
            private_key: hex::encode_upper(sk.as_bytes()),
        }
    }
    fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    // Add Error-Checking
    fn deserialize(yaml: &str) -> Self {
        let result: SphincsKeypair = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn public_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.public_key).unwrap()
    }
    fn secret_key_as_bytes(&self) -> Vec<u8> {
        log::warn!("[WARN|0x1000] The Secret Key For a SPHINCS+ Keypair Was Just Returned In Byte Form");
        return hex::decode(&self.private_key).unwrap()
    }
    fn sign(&self,message: &str) -> Signature {
        let x = sphincsshake256fsimple::detached_sign(message.as_bytes(), &sphincsshake256fsimple::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public_key: self.public_key.clone(), // Public Key Hex
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            is_str: true,
        }
    }
    fn sign_data<T: AsRef<[u8]>>(&self,data: T) -> Signature {
        let hex_hash = Self::data_as_hexadecimal_hash(data.as_ref());
        let signature = sphincsshake256fsimple::detached_sign(hex_hash.as_bytes(), &sphincsshake256fsimple::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());

        return Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.public_key.clone(),
            message: hex_hash,
            signature: base64::encode(signature.as_bytes()),
            is_str: false,
        }
    }
    fn sign_file<T: AsRef<Path>>(&self,path: T) -> Result<Signature,SeleniteErrors> {
        let does_file_exist: bool = path.as_ref().exists();

        if does_file_exist == false {
            return Err(SeleniteErrors::FileDoesNotExist)
        }

        let fbuffer = std::fs::read(path.as_ref()).expect("[Error] failed to open file");
        let hash = Self::data_as_hexadecimal_hash(&fbuffer);

        let signature = sphincsshake256fsimple::detached_sign(hash.as_bytes(), &sphincsshake256fsimple::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());

        return Ok(Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.return_public_key_as_hex(),
            message: hash,
            signature: base64::encode(signature.as_bytes()),
            is_str: false,
        })
    }
    fn decode_from_hex(s: String) -> Result<Vec<u8>,SeleniteErrors> {
        let h = hex::decode(s);
        match h {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SeleniteErrors::DecodingFromHexFailed)
        }
    }
    fn return_public_key_as_hex(&self) -> String {
        return self.public_key.clone()
    }
    fn return_secret_key_as_hex(&self) -> String {
        log::warn!("[WARN|0x1000] The Secret Key For a SPHINCS+ Keypair Was Just Returned In Hexadecimal Form");
        return self.private_key.clone()
    }
    fn data_as_hexadecimal_hash(data: &[u8]) -> String {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let hex_hash: String = hex::encode_upper(hash.as_bytes());
        return hex_hash
    }
    fn data_as_hash(data: &[u8]) -> Vec<u8> {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let bytes = hash.as_bytes();
        return bytes.to_vec()
    }
    fn construct_from<T: AsRef<str>>(pk: T, sk: T) -> Self {
        return Self {
            algorithm: String::from(Self::ALGORITHM),
            public_key: pk.as_ref().to_string(),
            private_key: sk.as_ref().to_string(),
        }
    }
}

impl Signatures for Signature {
    fn new(algorithm: &str, pk: &str, signature: &str, message: &str) -> Self {
        if algorithm == "SPHINCS+" || algorithm == "FALCON512" || algorithm == "FALCON1024" || algorithm == "ED25519" || algorithm == "BLS" {
            return Signature {
                algorithm: algorithm.to_owned(),
                public_key: pk.to_owned(),
                message: message.to_owned(),
                signature: signature.to_owned(),
                is_str: true,
            }
        }
        else {
            panic!("AlgorithmWrong")
        }
    }
    fn verify(&self) -> bool {
        if self.algorithm == "SPHINCS+" {
            let v: Result<(),VerificationError> = sphincsshake256fsimple::verify_detached_signature(&sphincsshake256fsimple::DetachedSignature::from_bytes(&base64::decode(&self.signature).unwrap()).unwrap(), &self.message.as_bytes(), &sphincsshake256fsimple::PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap());
            if v.is_err() {
                return false
            }
            else {
                return true
            }
        }
        else {
            panic!("[Verification|0x0000] Invalid Algorithm Type")
        }
    }
    fn deserialize(yaml: &str) -> Self {
        let result: Signature = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    fn deserialize_from_bincode(serde_bincode: Vec<u8>) -> Self {
        return bincode::deserialize(&serde_bincode[..]).unwrap();
    }
    fn serialize_to_bincode(&self) -> Vec<u8> {
        return bincode::serialize(&self).unwrap();
    }
    // Returns message as a byte array
    fn message_as_bytes(&self) -> &[u8] {
        return self.message.as_bytes()
    }
    // Returns Base64 decoded signature as a vector of bytes
    fn signature_as_bytes(&self) -> Vec<u8> {
        return base64::decode(&self.signature).unwrap()
    }
    fn compare_public_key(&self, pk: String) -> bool {
        if self.public_key == pk {
            return true
        }
        else {
            return false
        }
    }
    // Message is a UTF-8 Message / String
    fn compare_message(&self, msg: String) -> bool {
        if self.message == msg {
            return true
        }
        else {
            return false
        }
    }
    // Signature Is Encoded in Base64
    fn compare_signature(&self, signature: String) -> bool {
        if self.signature == signature {
            return true
        }
        else {
            return false
        }
    }
}

impl Verify {
    /// ## Verification
    /// Verifies Signatures by constructing them and returns a boolean.
    ///
    /// Currently does not allow verification of ED25519 (non pq crypto)
    pub fn new(algorithm: KeypairAlgorithms,pk: &str,signature: &str,message: &str) -> bool {

        let alg = match algorithm {
            KeypairAlgorithms::FALCON512 => "FALCON512",
            KeypairAlgorithms::FALCON1024 => "FALCON1024",
            KeypairAlgorithms::SphincsPlus => "SPHINCS+",

            // Not Post-Quantum
            KeypairAlgorithms::ED25519 => "ED25519",
            KeypairAlgorithms::BLS => "BLS",
        };

        log::info!("[INFO] Verifying Digital Signature: {}",&alg);
        log::info!("Public Key: {}",pk);
        log::info!("Signature: {}",signature);
        log::info!("Message: {}",message);

        // PK (HEX) | SIG (BASE64) | MESSAGE
        let pk_bytes = hex::decode(pk).unwrap();
        let signature_bytes = base64::decode(signature).unwrap();
        let message_bytes = message.as_bytes();

        if alg == "SPHINCS+" {
            let v: Result<(),VerificationError> = sphincsshake256fsimple::verify_detached_signature(&sphincsshake256fsimple::DetachedSignature::from_bytes(&signature_bytes).unwrap(), message_bytes, &sphincsshake256fsimple::PublicKey::from_bytes(&pk_bytes).unwrap());
            if v.is_err() {
                return false
            }
            else {
                return true
            }
        }
        else {
            panic!("Cannot Read Algorithm Type")
        }
    }
    /// ## Determines Public Key Algorithm
    /// This determines the public key algorithm based on its key size (in hexadecimal) and returns a `KeypairAlgorithm` enum.
    pub fn determine_algorithm(pk: &str) -> KeypairAlgorithms {
        let length = pk.len();

        if length == 128 {
            return KeypairAlgorithms::SphincsPlus
        }
        else if length > 1500 && length < 2000 {
            return KeypairAlgorithms::FALCON512
        }
        else {
            return KeypairAlgorithms::FALCON1024
        }
    }
}

// #[test]
// fn generate(){
//     let mut keypair = BLSKeypair::new();
//     let sig1 = keypair.sign("Hello World");
// 
//     let mut keypair2 = BLSKeypair::new();
//     let sig2 = keypair2.sign("Hello");
// 
//     let f = sig1.signature_as_bytes();
//     let final_sig1 = bls_signatures::Signature::from_bytes(&f).unwrap();
//     let final_pk = bls_signatures::PublicKey::from_bytes(&keypair.public_key_as_bytes()).unwrap();
// 
//     let g = sig2.signature_as_bytes();
//     let final_sig2 = bls_signatures::Signature::from_bytes(&g).unwrap();
//     let final_pk2 = bls_signatures::PublicKey::from_bytes(&keypair2.public_key_as_bytes()).unwrap();
// 
//     let output = bls_signatures::aggregate(&vec![final_sig1,final_sig2]).unwrap();
// 
//     let is_valid = bls_signatures::verify_messages(&output, &[b"Hello World",b"Hello"], &[final_pk,final_pk2]);
// 
//     println!("Is Valid BLS Aggregation: {}",is_valid);
// }