use scope_interface::token_account::{CLOSE_ACCOUNT_INSTRUCTION, read_token_account};
use solana_address::Address;
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensionsMut, ExtensionType, StateWithExtensionsMut,
        confidential_transfer::ConfidentialTransferAccount,
    },
    instruction::close_account,
    state::{Account, AccountState},
};

#[test]
fn token_2022_id_matches() {
    assert_eq!(
        scope_interface::TOKEN_2022_ID,
        spl_token_2022_interface::id().to_bytes()
    );
}

#[test]
fn program_id_bytes_match_base58() {
    let id: Address = scope_interface::ID_BASE58.parse().expect("base58");
    assert_eq!(id.to_bytes(), scope_interface::ID);
}

#[test]
fn close_account_byte_matches() {
    let a = Address::new_unique();
    let ix = close_account(&spl_token_2022_interface::id(), &a, &a, &a, &[]).expect("ix");
    assert_eq!(ix.data, vec![CLOSE_ACCOUNT_INSTRUCTION]);
}

#[test]
fn reader_agrees_with_official_unpack() {
    let len = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])
    .expect("len");
    assert_eq!(len, 465);
    let mut data = vec![0u8; len];
    let owner = Address::new_unique();
    let close = Address::new_unique();
    {
        let mut state =
            StateWithExtensionsMut::<Account>::unpack_uninitialized(&mut data).expect("unpack");
        let ct = state
            .init_extension::<ConfidentialTransferAccount>(true)
            .expect("ext");
        ct.approved = true.into();
        ct.allow_confidential_credits = true.into();
        ct.allow_non_confidential_credits = false.into();
        ct.maximum_pending_balance_credit_counter = 1u64.into();
        state.base.owner = owner;
        state.base.state = AccountState::Initialized;
        state.base.close_authority = Some(close).into();
        state.pack_base();
        state.init_account_type().expect("type");
    }
    let v = read_token_account(&data).expect("read");
    assert_eq!(v.owner, owner.to_bytes());
    assert_eq!(v.close_authority, Some(close.to_bytes()));
    let ct = v.confidential.expect("ct");
    assert!(ct.approved && !ct.allow_non_confidential_credits);
    assert_eq!(ct.maximum_pending_balance_credit_counter, 1);
}
