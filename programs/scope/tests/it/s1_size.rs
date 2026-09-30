use crate::s3_sweep::{payer_ixs, recipient_ixs};
use scope_client::{
    address::announcement_address,
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

/// S5: the same transactions are measured and sent. The case is pinned to canonical
/// bump 255, since each lower bump adds about 1,500 CU to `announce`.
#[test]
fn s5_both_stealth_transactions_fit_and_are_measured() {
    let mut h = Harness::new();
    let case = loop {
        let case = h.stealth_case();
        if announcement_address(&case.token_account).1 == 255 {
            break case;
        }
    };
    let payer_tx = v1_transaction(
        &h.payer,
        &[],
        &payer_ixs(&h, &case),
        h.svm.latest_blockhash(),
    );
    let payer_bytes = wire_bytes(&payer_tx);
    let payer_meta = h.svm.send_transaction(payer_tx).expect("payer tx lands");

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
    let recipient_meta = h
        .svm
        .send_transaction(recipient_tx)
        .expect("recipient tx lands");

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
        "S5 at bump 255: payer {} bytes {} CU, recipient {} bytes {} CU",
        payer_bytes.len(),
        payer_meta.compute_units_consumed,
        recipient_bytes.len(),
        recipient_meta.compute_units_consumed,
    );
}
