use crate::s3_sweep::{pay, payer_ixs, recipient_ixs};
use scope_client::{
    testkit::Harness,
    tx::{v1_transaction, v1_wire_size},
};
use solana_keypair::Keypair;
use solana_transaction::versioned::VersionedTransaction;
use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};

/// v1 transaction limit (solana-message v1::MAX_TRANSACTION_SIZE); LiteSVM does not enforce it.
const MAX_TX_BYTES: usize = 4096;

fn wire_bytes(tx: &VersionedTransaction) -> Vec<u8> {
    let bytes = wincode::serialize(tx).expect("serialize");
    assert_eq!(
        bytes.len(),
        v1_wire_size(tx),
        "v1_wire_size matches the wire"
    );
    bytes
}

#[test]
fn s1_both_stealth_transactions_fit_4096_bytes() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    let payer_tx = v1_transaction(
        &h.payer,
        &[],
        &payer_ixs(&h, &case),
        h.svm.latest_blockhash(),
    );
    let payer_bytes = wire_bytes(&payer_tx);
    pay(&mut h, &case);

    let d_owner = Keypair::new();
    let (d_keys, d_ae) = (ElGamalKeypair::new_rand(), AeKey::new_rand());
    let d = h.plain_confidential_account(&d_owner, &d_keys, &d_ae);
    let recipient_tx = v1_transaction(
        &case.one_time_owner,
        &[],
        &recipient_ixs(&h, &case, &d, d_keys.pubkey()),
        h.svm.latest_blockhash(),
    );
    let recipient_bytes = wire_bytes(&recipient_tx);

    assert!(
        payer_bytes.len() <= MAX_TX_BYTES,
        "payer tx {} bytes",
        payer_bytes.len()
    );
    assert!(
        recipient_bytes.len() <= MAX_TX_BYTES,
        "recipient tx {} bytes",
        recipient_bytes.len()
    );
    println!(
        "payer {} bytes, recipient {} bytes",
        payer_bytes.len(),
        recipient_bytes.len()
    );
}
