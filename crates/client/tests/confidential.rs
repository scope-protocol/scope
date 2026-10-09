//! Public API from stealth discovery through SDK encryption and disclosure.

use rand_core::{TryCryptoRng, TryRng};
use scope_client::confidential::derive_confidential_keys;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_zk_sdk::{
    encryption::auth_encryption::AeCiphertext,
    zk_elgamal_proof_program::{VerifyZkProof, build_pubkey_validity_proof_data},
};
use stealth_keygen::{
    ConfidentialContext, ConfidentialKeyMaterial, EphemeralSecret, RecipientSecretKeys,
    derive_payment, derive_payment_with_ephemeral, recover_payment,
};

// Fixed bytes for tests only. Never use this RNG with real keys.
struct TestRng(u8);

impl TryRng for TestRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        out.fill(self.0);
        self.0 += 1;
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

#[test]
fn sweep_destination_seed_builds_a_solana_signer() {
    let recipient = RecipientSecretKeys::generate(&mut TestRng(1)).expect("recipient");
    let sent = derive_payment(&recipient.derive_public_keys(), &mut TestRng(3)).expect("payment");
    let seed = recipient
        .derive_sweep_destination(&sent.announcement.ephemeral_public_key, &[4; 32])
        .expect("sweep seed");
    let owner = Keypair::new_from_array(*seed.as_bytes());
    let restored =
        RecipientSecretKeys::from_bytes(*recipient.export().as_bytes()).expect("restore");
    let rebuilt_seed = restored
        .derive_sweep_destination(&sent.announcement.ephemeral_public_key, &[4; 32])
        .expect("rebuilt sweep seed");
    let rebuilt = Keypair::new_from_array(*rebuilt_seed.as_bytes());
    assert_eq!(owner.pubkey(), rebuilt.pubkey());
    assert_ne!(owner.pubkey().to_bytes(), sent.payment_public_key);
    let message = b"sweep transaction message";
    let signature = owner.sign_message(message);
    assert_eq!(signature, rebuilt.sign_message(message));
    assert!(signature.verify(owner.pubkey().as_ref(), message));
}

#[test]
fn recovered_payment_signs_a_solana_transaction_with_the_protocol_context() {
    use scope_client::{
        confidential::context,
        signer::PaymentSigner,
        tx::{DEFAULT_CU_LIMIT, signed_v1_transaction},
    };
    use solana_address::Address;
    let recipient = RecipientSecretKeys::generate(&mut TestRng(1)).expect("recipient");
    let sent = derive_payment(&recipient.derive_public_keys(), &mut TestRng(3)).expect("payment");
    let mint = Address::new_from_array([7; 32]);
    let account = Address::new_from_array([8; 32]);
    let ctx = context([9; 32], &mint, &account);
    assert_eq!(ctx.program_id, scope_interface::ID);
    let recovered = recover_payment(&recipient, &sent.announcement)
        .expect("recover")
        .expect("ours");
    assert_eq!(
        sent.derive_ct_ikm(&ctx).expect("payer").as_bytes(),
        recovered.derive_ct_ikm(&ctx).expect("recipient").as_bytes()
    );
    let signer = PaymentSigner::new(&recovered);
    let destination = Keypair::new();
    let ix =
        solana_system_interface::instruction::transfer(&signer.pubkey(), &destination.pubkey(), 1);
    let tx = signed_v1_transaction(
        &signer,
        &[],
        &[ix],
        solana_message::Hash::default(),
        DEFAULT_CU_LIMIT,
        None,
    )
    .expect("transaction");
    assert!(tx.signatures[0].verify(signer.pubkey().as_ref(), &tx.message.serialize()));
    let wrong_message = b"another transaction";
    assert!(!tx.signatures[0].verify(signer.pubkey().as_ref(), wrong_message));
}

#[test]
fn payer_recipient_and_disclosure_derive_the_same_usable_keys() {
    let recipient = RecipientSecretKeys::generate(&mut TestRng(1)).expect("recipient");
    let sent = derive_payment(&recipient.derive_public_keys(), &mut TestRng(3)).expect("payment");
    let rebuilt = derive_payment_with_ephemeral(
        &recipient.derive_public_keys(),
        &EphemeralSecret::from_bytes([3; 32]),
    )
    .expect("rebuilt payment");
    assert_eq!(rebuilt.announcement, sent.announcement);
    assert_eq!(rebuilt.payment_public_key, sent.payment_public_key);
    let recovered = recover_payment(&recipient, &sent.announcement)
        .expect("recovery")
        .expect("matching tag");
    let context = ConfidentialContext {
        chain_id: [1; 32],
        program_id: [2; 32],
        mint: [3; 32],
        token_account: [4; 32],
    };
    let material = sent.derive_ct_ikm(&context).expect("payer material");
    let received = recovered
        .derive_ct_ikm(&context)
        .expect("recipient material");
    let resumed = rebuilt.derive_ct_ikm(&context).expect("rebuilt material");
    assert_eq!(resumed.as_bytes(), material.as_bytes());
    let disclosed = ConfidentialKeyMaterial::from_bytes(*material.as_bytes());
    let (payer_eg, payer_ae) = derive_confidential_keys(&material).expect("payer keys");
    for input in [&received, &resumed, &disclosed] {
        let (eg, ae) = derive_confidential_keys(input).expect("derived keys");
        assert_eq!(eg, payer_eg);
        assert_eq!(ae, payer_ae);
        for amount in [0, 1, 42, 65_535] {
            assert_eq!(
                eg.secret()
                    .decrypt_u32(&payer_eg.pubkey().encrypt_u64(amount)),
                Some(amount)
            );
        }
        for amount in [0, 1, 42, u32::MAX as u64, u64::MAX] {
            assert_eq!(ae.decrypt(&payer_ae.encrypt(amount)), Some(amount));
        }
    }
    build_pubkey_validity_proof_data(&payer_eg)
        .expect("pubkey proof")
        .verify_proof()
        .expect("valid proof");

    // A receipt containing different material fails the public-key comparison.
    let mut forged = *disclosed.as_bytes();
    forged[0] ^= 1;
    let (forged_eg, _) = derive_confidential_keys(&ConfidentialKeyMaterial::from_bytes(forged))
        .expect("forged keys");
    assert_ne!(forged_eg.pubkey(), payer_eg.pubkey());

    let changed = ConfidentialContext {
        token_account: [5; 32],
        ..context
    };
    let changed_material = recovered.derive_ct_ikm(&changed).expect("changed context");
    let (other_eg, other_ae) = derive_confidential_keys(&changed_material).expect("other keys");
    assert_ne!(other_eg.pubkey(), payer_eg.pubkey());
    assert_eq!(other_ae.decrypt(&payer_ae.encrypt(42)), None);
    let ciphertext = payer_ae.encrypt(42).to_bytes();
    for i in 0..ciphertext.len() {
        let mut corrupted = ciphertext;
        corrupted[i] ^= 1;
        let parsed = AeCiphertext::from_bytes(&corrupted).expect("ciphertext encoding");
        assert_eq!(payer_ae.decrypt(&parsed), None);
    }
}

#[test]
fn sdk_decryption_covers_pending_component_boundaries() {
    let keys = solana_zk_sdk::encryption::elgamal::ElGamalKeypair::new_rand();
    for amount in [65_535, 65_536, 131_071, 131_072, u64::from(u32::MAX)] {
        assert_eq!(
            keys.secret()
                .decrypt_u32(&keys.pubkey().encrypt_u64(amount)),
            Some(amount)
        );
    }
}
