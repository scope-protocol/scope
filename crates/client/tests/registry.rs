//! Publishing a meta-address, looking it up, and paying it.

use scope_client::{
    ix,
    pay::{self, PayOptions, SourceKeys},
    registry, scan,
    testkit::{Harness, SvmChain},
};
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::time::Duration;
use stealth_keygen::RecipientSecretKeys;

#[test]
fn a_payer_looks_up_a_published_meta_address_and_pays_it() {
    let mut h = Harness::new();
    let alice = RecipientSecretKeys::from_bytes([4; 64]).expect("test secrets");
    let wallet = Keypair::new();
    h.svm
        .airdrop(&wallet.pubkey(), 1_000_000_000)
        .expect("fund");
    h.send(
        &[ix::register(&wallet.pubkey(), &alice.derive_public_keys())],
        &[&wallet],
    )
    .expect("publish");

    let nobody = Keypair::new().pubkey();
    let found =
        registry::lookup(&SvmChain::new(&mut h.svm), &[wallet.pubkey(), nobody]).expect("lookup");
    assert_eq!(found[0].1, Some(alice.derive_public_keys()));
    assert_eq!(found[1].1, None);

    let meta = found[0].1.as_ref().expect("published").to_meta_address();
    let opts = PayOptions {
        runs_dir: std::env::temp_dir().join(format!("scope-registry-{}", std::process::id())),
        max_price_per_cu: 1_000_000,
        poll: Duration::ZERO,
        again: false,
        log: |_| {},
    };
    let _ = std::fs::remove_dir_all(&opts.runs_dir);
    let (mint, source) = (h.mint, h.source);
    let keys = SourceKeys {
        elgamal: h.source_elgamal.clone(),
        ae: h.source_ae.clone(),
    };
    pay::start(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys,
        mint,
        source,
        format!("{meta},2\n").as_bytes(),
        &opts,
    )
    .expect("pay");
    let payments = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect("scan");
    assert_eq!(payments.payments.len(), 1);
    assert_eq!(payments.payments[0].amount, 2_000_000);

    h.send(&[ix::deregister(&wallet.pubkey())], &[&wallet])
        .expect("unpublish");
    let found = registry::lookup(&SvmChain::new(&mut h.svm), &[wallet.pubkey()]).expect("lookup");
    assert_eq!(found[0].1, None, "gone after deregister");
}
