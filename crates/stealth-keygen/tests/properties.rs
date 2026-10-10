//! Properties over random key material: payer and recipient agree, and the one-time
//! key signs for the address the payer computed.

#[path = "../src/test_support.rs"]
#[allow(dead_code)]
mod support;

use ed25519_dalek::VerifyingKey;
use proptest::prelude::*;
use stealth_keygen::{
    ConfidentialContext, RecipientPublicKeys, RecipientSecretKeys, derive_payment, recover_payment,
};
use support::ScriptedRng;

fn recipient(entropy: &[u8]) -> Option<RecipientSecretKeys> {
    RecipientSecretKeys::generate(&mut ScriptedRng::new(entropy)).ok()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn payer_and_recipient_agree_and_the_one_time_key_signs(
        identity in proptest::collection::vec(any::<u8>(), 256),
        payment in proptest::collection::vec(any::<u8>(), 128),
        mint in any::<[u8; 32]>(),
        account in any::<[u8; 32]>(),
        message in proptest::collection::vec(any::<u8>(), 0..96),
    ) {
        let recipient = recipient(&identity);
        prop_assume!(recipient.is_some());
        let recipient = recipient.unwrap();
        let public = recipient.derive_public_keys();
        let sent = derive_payment(&public, &mut ScriptedRng::new(payment));
        prop_assume!(sent.is_ok());
        let sent = sent.unwrap();

        let found = recover_payment(&recipient, &sent.announcement).unwrap();
        prop_assert!(found.is_some(), "the recipient always finds a payment made to them");
        let found = found.unwrap();
        prop_assert_eq!(found.payment_public_key, sent.payment_public_key);

        let signature = found.sign(&message);
        let key = VerifyingKey::from_bytes(&sent.payment_public_key).unwrap();
        prop_assert!(
            key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&signature)).is_ok()
        );

        let context = ConfidentialContext {
            chain_id: [9; 32],
            program_id: [8; 32],
            mint,
            token_account: account,
        };
        let (theirs, ours) = (
            found.derive_ct_ikm(&context).unwrap(),
            sent.derive_ct_ikm(&context).unwrap(),
        );
        prop_assert_eq!(theirs.as_bytes(), ours.as_bytes());

        let r = sent.announcement.ephemeral_public_key;
        let seed = recipient.derive_sweep_destination(&r, &account).unwrap();
        let again = recipient.derive_sweep_destination(&r, &account).unwrap();
        prop_assert_eq!(seed.as_bytes(), again.as_bytes());
        let mut other = account;
        other[0] ^= 1;
        let different = recipient.derive_sweep_destination(&r, &other).unwrap();
        prop_assert_ne!(seed.as_bytes(), different.as_bytes());
    }

    #[test]
    fn meta_addresses_round_trip_and_reject_any_flipped_character(
        identity in proptest::collection::vec(any::<u8>(), 256),
        position in any::<proptest::sample::Index>(),
    ) {
        let recipient = recipient(&identity);
        prop_assume!(recipient.is_some());
        let public = recipient.unwrap().derive_public_keys();
        let address = public.to_meta_address();
        prop_assert_eq!(RecipientPublicKeys::from_meta_address(&address).unwrap(), public);
        let body = address.strip_prefix("scope:").unwrap();
        let i = position.index(body.len());
        let mut chars: Vec<char> = body.chars().collect();
        chars[i] = if chars[i] == '2' { '3' } else { '2' };
        let altered = format!("scope:{}", chars.into_iter().collect::<String>());
        prop_assert!(RecipientPublicKeys::from_meta_address(&altered).is_err());
    }
}

/// A one-byte tag collides for about 1 in 256 strangers. Grind one that does, then check
/// that it still derives a different one-time key.
#[test]
fn a_stranger_whose_tag_collides_still_gets_a_different_key() {
    let owner = recipient(&[7u8; 256]).expect("recipient");
    let sent = derive_payment(
        &owner.derive_public_keys(),
        &mut ScriptedRng::new([9u8; 128]),
    )
    .expect("payment");
    let mut collisions = 0;
    for seed in 0..4096u32 {
        let mut entropy = [0u8; 256];
        for (i, chunk) in entropy.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&(seed ^ ((i as u32) << 16)).to_le_bytes());
        }
        let Some(stranger) = recipient(&entropy) else {
            continue;
        };
        if let Some(found) = recover_payment(&stranger, &sent.announcement).unwrap() {
            collisions += 1;
            assert_ne!(found.payment_public_key, sent.payment_public_key);
        }
    }
    assert!(collisions > 0, "no stranger collided in 4096 tries");
}
