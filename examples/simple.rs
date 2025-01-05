#![cfg(any(feature = "in-memory", feature = "in-disk"))]

use dgsp::dgsp::DGSP;
use dgsp::{Error, PLMInterface, RevokedListInterface};
use std::path::PathBuf;

use dgsp::VerificationError::RevokedSignature;
#[cfg(feature = "in-disk")]
use dgsp::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-memory")]
use dgsp::{InMemoryPLM, InMemoryRevokedList};

// Replace this with in-disk if you want to use in-disk features
#[cfg(feature = "in-memory")]
async fn simple_dgsp() {
    // Choose a path for PLM and RevokedList database storage
    // As an example, we choose the project directory and create a database path.
    // Note that it is only needed for in-disk db, so uncomment it if you want an in-disk db.
    // let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/simple_db");

    // Here we set PLM to store in-memory.
    let plm = InMemoryPLM::open("").await.unwrap();
    // You can use in-disk PLM instead like this:
    // let plm = InDiskPLM::open(&path).await.unwrap();

    // The in-memory RevokedList.
    let revoked_list = InMemoryRevokedList::open("").await.unwrap();
    // The in-disk RevokedList.
    // let revoked_list = InDiskRevokedList::open(&path).await.unwrap();

    // Note that plm and revoked_list can have different storage types
    // and still work  perfectly fine with each other.

    // Create manager key pair:
    let (pkm, skm) = DGSP::keygen_manager().unwrap();

    // Now a user chooses a username and requests to join DGSP scheme.
    let username = "DGSP User 1";
    let (id, cid) = DGSP::join(&skm.msk, username, &plm).await.unwrap();

    // The user then runs their keygen to obtain a private seed.
    let seed_u = DGSP::keygen_user();

    // Next, user creates a batch of 2 certificate signing requests,
    // including 2 pairs of WOTS+ public-key and corresponding randomness.
    let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 2);

    // The user then requests a batch of certificates for the 2 WOTS+ public keys created.
    let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk)
        .await
        .unwrap();

    // After receiving certificates, user can sign an arbitrary message.
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg1 = "Hi! I am DGSP User 1. This is my first message!".as_bytes();
    let sig1 = DGSP::sign(msg1, wots_rand, &seed_u, cert);

    // Now having the public information, one can verify the user's signature:
    assert_eq!(DGSP::verify(msg1, &sig1, &revoked_list, &pkm).await, Ok(()));
    // By receiving no error, one can make sure the sig1 is valid signature of msg1.

    // Now user creates another signature:
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg2 = "I am still DGSP User 1 and this is my second message. :)".as_bytes();
    let sig2 = DGSP::sign(msg2, wots_rand, &seed_u, cert);
    assert_eq!(DGSP::verify(msg2, &sig2, &revoked_list, &pkm).await, Ok(()));

    // The user then wants to sign again.
    let cert = certs.pop();
    assert!(cert.is_none());
    // Oh, no! No certificates remained for the user.

    // User then asks for a few more certificates from the DGSP manager.
    let (wots_pks, mut wots_rands) = DGSP::cert_sign_req_user(&seed_u, 5);
    let mut certs = DGSP::req_cert(&skm.msk, id, cid, &wots_pks, &plm, &skm.spx_sk)
        .await
        .unwrap();

    // Now user can continue signing messages.
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg3 = "I am yet again DGSP User 1 and this is my third message. ciao!".as_bytes();
    let sig3 = DGSP::sign(msg3, wots_rand, &seed_u, cert);
    assert_eq!(DGSP::verify(msg3, &sig3, &revoked_list, &pkm).await, Ok(()));

    // The DGSP manager then decides to open sig3 to see who has signed it.
    let (signer_id, signer_username) = DGSP::open(&skm.msk, &plm, &sig3).await.unwrap();
    // Oh hey, it is "DGSP User 1"!
    assert_eq!(signer_id, id);
    assert_eq!(signer_username, username);

    // After a while, user membership in the group expires
    // and as so, manager decides to revoke its membership
    // and the corresponding generated signatures and certificates
    DGSP::revoke(&skm.msk, &plm, vec![id], &revoked_list)
        .await
        .unwrap();

    // After that, the user's previous signatures will no longer be verified.
    assert_eq!(
        DGSP::verify(msg1, &sig1, &revoked_list, &pkm).await,
        Err(Error::VerificationFailed(RevokedSignature))
    );
    assert_eq!(
        DGSP::verify(msg2, &sig2, &revoked_list, &pkm).await,
        Err(Error::VerificationFailed(RevokedSignature))
    );
    assert_eq!(
        DGSP::verify(msg3, &sig3, &revoked_list, &pkm).await,
        Err(Error::VerificationFailed(RevokedSignature))
    );

    // And user can no longer create valid signatures using the remaining certificates:
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // #[cfg(feature = "in-memory")]
    // verify_in_memory_benchmark().await;
    //
    // #[cfg(feature = "in-disk")]
    // verify_in_disk_benchmark().await;
}
