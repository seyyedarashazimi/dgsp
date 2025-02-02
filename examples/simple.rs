use dgsp::dgsp::DGSP;
use dgsp::{PLMInterface, RevokedListInterface};

#[cfg(feature = "in-memory")]
use dgsp::{InMemoryPLM, InMemoryRevokedList};

#[cfg(feature = "in-disk")]
use dgsp::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-disk")]
use std::path::PathBuf;

#[cfg(feature = "in-memory")]
fn simple_dgsp_in_memory() {
    println!("--------------------------------------");
    println!("DGSP Manager log (in-memory database):");
    // Here we set PLM to store in-memory.
    let plm = InMemoryPLM::open("").unwrap();

    // The in-memory RevokedList.
    let revoked_list = InMemoryRevokedList::open("").unwrap();

    println!("DGSP in-memory PLM and RevokedList launched successfully.");

    // Note that plm and revoked_list can have different storage types
    // and still work perfectly fine with each other.

    // Create manager key pair:
    let (pkm, skm) = DGSP::keygen_manager().unwrap();
    println!("Constructed PublicKey and SecretKey pair for the manager.");

    // Now a user chooses a username and requests to join DGSP scheme.
    let username = "DGSP User 1";
    let (id, cid) = DGSP::join(&skm.msk, username, &plm).unwrap();
    println!(
        "User with username:{:?} joined DGSP with id:{}.",
        username, id
    );

    // The user then runs their keygen to obtain a private seed.
    let seed_u = DGSP::keygen_user();

    // Next, user creates a batch of 2 certificate signing requests,
    // including 2 pairs of WOTS+ public-key and corresponding randomness.
    let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, 2);

    // The user then requests a batch of certificates for the 2 WOTS+ public keys created.
    let mut certs = DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
    println!(
        "Created {} new certificates for {:?}, requested by the user.",
        certs.len(),
        username
    );

    // User can at any time check the given certificates to be sure they are correctly created.
    println!(
        "The status of checking {} certificates: {:?}.",
        certs.len(),
        DGSP::check_cert(id, &cid, &wots_pks, &certs, &pkm)
    );

    // After receiving certificates, user can sign an arbitrary message.
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg1 = "Hi! I am DGSP User 1. This is my first message!".as_bytes();
    let sig1 = DGSP::sign(msg1, &seed_u, id, &cid, wots_rand, cert);

    // Now having the public information, one can verify the user's signature:
    println!(
        "Verification status of the first signature of {:?}: {:?}.",
        username,
        DGSP::verify(msg1, &sig1, &revoked_list, &pkm)
    );
    // By receiving no error, one can make sure the sig1 is a valid signature for msg1.

    // Now user creates another signature:
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg2 = "I am still DGSP User 1 and this is my second message. :)".as_bytes();
    let sig2 = DGSP::sign(msg2, &seed_u, id, &cid, wots_rand, cert);
    println!(
        "Verification status of the second signature of {:?}: {:?}.",
        username,
        DGSP::verify(msg2, &sig2, &revoked_list, &pkm)
    );

    // The user then wants to sign again.
    let cert = certs.pop();
    println!("Remaining certificates for {:?}: {:?}.", username, cert);
    // Oh, no! No certificates remained for the user.

    // User then asks for a few more certificates from the DGSP manager.
    let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, 5);
    let mut certs = DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
    println!(
        "Created {} new certificates for {:?}, requested by the user.",
        certs.len(),
        username
    );

    // Now user can continue signing messages.
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg3 = "I am yet again DGSP User 1 and this is my third message. ciao!".as_bytes();
    let sig3 = DGSP::sign(msg3, &seed_u, id, &cid, wots_rand, cert);
    println!(
        "Verification status of the third signature of {:?}: {:?}.",
        username,
        DGSP::verify(msg3, &sig3, &revoked_list, &pkm)
    );

    // The DGSP manager then decides to open sig3 to see who has signed it.
    let (signer_id, signer_username, proof) = DGSP::open(&skm.msk, &plm, &sig3, msg3).unwrap();
    println!(
        "Manager opened third signature to find who has signed it: signer_username:{:?}, signer_id:{}.",
        signer_username, signer_id
    );
    // Oh hey, it is "DGSP User 1"!

    // Let's make judge manager by making sure manager has opened the signature to correct id
    println!(
        "Manager opened signature to user id:{}, judge manager open behavior: {:?}.",
        id,
        DGSP::judge(&sig3, msg3, id, &proof)
    );

    // After a while, user membership in the group expires
    // and as so, manager decides to revoke its membership
    // and the corresponding generated signatures and certificates
    DGSP::revoke(&skm.msk, &plm, &[id], &revoked_list).unwrap();
    println!("User {:?} is revoked from now on.", username);

    // After that, the user's previous signatures will no longer be verified.
    println!(
        "Verification status of the first  signature of {:?} after revocation: {:?}.",
        username,
        DGSP::verify(msg1, &sig1, &revoked_list, &pkm)
    );
    println!(
        "Verification status of the second signature of {:?} after revocation: {:?}.",
        username,
        DGSP::verify(msg2, &sig2, &revoked_list, &pkm)
    );
    println!(
        "Verification status of the third  signature of {:?} after revocation: {:?}.",
        username,
        DGSP::verify(msg3, &sig3, &revoked_list, &pkm)
    );

    // And user can no longer create valid signatures using the remaining certificates:
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg4 = "This is DGSP User 1 and I am trying to sign even after being revoked!".as_bytes();
    let sig4 = DGSP::sign(msg4, &seed_u, id, &cid, wots_rand, cert);
    println!(
        "Verification status of the new signature signed by {:?} after revocation: {:?}.",
        username,
        DGSP::verify(msg4, &sig4, &revoked_list, &pkm)
    );
}

#[cfg(feature = "in-disk")]
fn simple_dgsp_in_disk() {
    println!("------------------------------------");
    println!("DGSP Manager log (in-disk database):");
    // Choose a path for PLM and RevokedList database storage
    // As an example, we choose the project directory and create a database path.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/simple_db");

    // Here we set PLM to store in-disk.
    let plm = InDiskPLM::open(&path).unwrap();

    // The in-disk RevokedList.
    let revoked_list = InDiskRevokedList::open(&path).unwrap();

    println!("DGSP in-disk PLM and RevokedList launched successfully.");

    // Note that plm and revoked_list can have different storage types
    // and still work perfectly fine with each other.

    // Create manager key pair:
    let (pkm, skm) = DGSP::keygen_manager().unwrap();
    println!("Constructed PublicKey and SecretKey pair for the manager.");

    // Now a user chooses a username and requests to join DGSP scheme.
    let username = "DGSP User 1";
    let (id, cid) = DGSP::join(&skm.msk, username, &plm).unwrap();
    // If the above line throws an Err(Error::UsernameAlreadyExists("<USERNAME>")) error, it means
    // you have run this code previously and there already exists a user with the given <USERNAME>.
    // So you can either remove the created database (default name is 'simple_db'), or choose
    // another path for database, or choose a new username.

    println!(
        "User with username:{:?} joined DGSP with id:{}.",
        username, id
    );

    // The user then runs their keygen to obtain a private seed.
    let seed_u = DGSP::keygen_user();

    // Next, user creates a batch of 2 certificate signing requests,
    // including 2 pairs of WOTS+ public-key and corresponding randomness.
    let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, 2);

    // The user then requests a batch of certificates for the 2 WOTS+ public keys created.
    let mut certs = DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
    println!(
        "Created {} new certificates for {:?}, requested by the user.",
        certs.len(),
        username
    );

    // User can at any time check the given certificates to be sure they are correctly created.
    println!(
        "The status of checking {} certificates: {:?}.",
        certs.len(),
        DGSP::check_cert(id, &cid, &wots_pks, &certs, &pkm)
    );

    // After receiving certificates, user can sign an arbitrary message.
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg1 = "Hi! I am DGSP User 1. This is my first message!".as_bytes();
    let sig1 = DGSP::sign(msg1, &seed_u, id, &cid, wots_rand, cert);

    // Now having the public information, one can verify the user's signature:
    println!(
        "Verification status of the first signature of {:?}: {:?}.",
        username,
        DGSP::verify(msg1, &sig1, &revoked_list, &pkm)
    );
    // By receiving no error, one can make sure the sig1 is a valid signature for msg1.

    // Now user creates another signature:
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg2 = "I am still DGSP User 1 and this is my second message. :)".as_bytes();
    let sig2 = DGSP::sign(msg2, &seed_u, id, &cid, wots_rand, cert);
    println!(
        "Verification status of the second signature of {:?}: {:?}.",
        username,
        DGSP::verify(msg2, &sig2, &revoked_list, &pkm)
    );

    // The user then wants to sign again.
    let cert = certs.pop();
    println!("Remaining certificates for {:?}: {:?}.", username, cert);
    // Oh, no! No certificates remained for the user.

    // User then asks for a few more certificates from the DGSP manager.
    let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u, 5);
    let mut certs = DGSP::gen_cert(&skm.msk, id, &cid, &wots_pks, &plm, &skm.spx_sk).unwrap();
    println!(
        "Created {} new certificates for {:?}, requested by the user.",
        certs.len(),
        username
    );

    // Now user can continue signing messages.
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg3 = "I am yet again DGSP User 1 and this is my third message. ciao!".as_bytes();
    let sig3 = DGSP::sign(msg3, &seed_u, id, &cid, wots_rand, cert);
    println!(
        "Verification status of the third signature of {:?}: {:?}.",
        username,
        DGSP::verify(msg3, &sig3, &revoked_list, &pkm)
    );

    // The DGSP manager then decides to open sig3 to see who has signed it.
    let (signer_id, signer_username, proof) = DGSP::open(&skm.msk, &plm, &sig3, msg3).unwrap();
    println!(
        "Manager opened third signature to find who has signed it: signer_username:{:?}, signer_id:{}.",
        signer_username, signer_id
    );
    // Oh hey, it is "DGSP User 1"!

    // Let's make judge manager by making sure manager has opened the signature to correct id
    println!(
        "Manager opened signature to user id:{}, judge manager open behavior: {:?}.",
        id,
        DGSP::judge(&sig3, msg3, id, &proof)
    );

    // After a while, user membership in the group expires
    // and as so, manager decides to revoke its membership
    // and the corresponding generated signatures and certificates
    DGSP::revoke(&skm.msk, &plm, &[id], &revoked_list).unwrap();
    println!("User {:?} is revoked from now on.", username);

    // After that, the user's previous signatures will no longer be verified.
    println!(
        "Verification status of the first  signature of {:?} after revocation: {:?}.",
        username,
        DGSP::verify(msg1, &sig1, &revoked_list, &pkm)
    );
    println!(
        "Verification status of the second signature of {:?} after revocation: {:?}.",
        username,
        DGSP::verify(msg2, &sig2, &revoked_list, &pkm)
    );
    println!(
        "Verification status of the third  signature of {:?} after revocation: {:?}.",
        username,
        DGSP::verify(msg3, &sig3, &revoked_list, &pkm)
    );

    // And user can no longer create valid signatures using the remaining certificates:
    let cert = certs.pop().unwrap();
    let wots_rand = wots_rands.pop().unwrap();
    let msg4 = "This is DGSP User 1 and I am trying to sign even after being revoked!".as_bytes();
    let sig4 = DGSP::sign(msg4, &seed_u, id, &cid, wots_rand, cert);
    println!(
        "Verification status of the new signature signed by {:?} after revocation: {:?}.",
        username,
        DGSP::verify(msg4, &sig4, &revoked_list, &pkm)
    );
}

fn main() {
    #[cfg(feature = "in-memory")]
    simple_dgsp_in_memory();
    #[cfg(feature = "in-disk")]
    simple_dgsp_in_disk();
}
