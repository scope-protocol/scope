use scope_interface::token_account::{CLOSE_ACCOUNT_INSTRUCTION, read_token_account};
use solana_address::Address;
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, BaseStateWithExtensionsMut, ExtensionType, StateWithExtensions,
        StateWithExtensionsMut, confidential_transfer::ConfidentialTransferAccount,
    },
    instruction::close_account,
    state::{Account, AccountState},
};

use proptest::prelude::*;
use spl_token_2022_interface::extension::memo_transfer::MemoTransfer;

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

#[test]
fn reader_agrees_with_official_cpi_guard_in_either_tlv_order() {
    use spl_token_2022_interface::extension::cpi_guard::CpiGuard;
    for locked in [true, false] {
        for guard_first in [true, false] {
            let types = if guard_first {
                [
                    ExtensionType::CpiGuard,
                    ExtensionType::ConfidentialTransferAccount,
                ]
            } else {
                [
                    ExtensionType::ConfidentialTransferAccount,
                    ExtensionType::CpiGuard,
                ]
            };
            let len = ExtensionType::try_calculate_account_len::<Account>(&types).expect("len");
            let mut data = vec![0u8; len];
            {
                let mut state = StateWithExtensionsMut::<Account>::unpack_uninitialized(&mut data)
                    .expect("unpack");
                for ty in types {
                    if ty == ExtensionType::CpiGuard {
                        state
                            .init_extension::<CpiGuard>(true)
                            .expect("guard")
                            .lock_cpi = locked.into();
                    } else {
                        state
                            .init_extension::<ConfidentialTransferAccount>(true)
                            .expect("ct");
                    }
                }
                state.base.state = AccountState::Initialized;
                state.pack_base();
                state.init_account_type().expect("type");
            }
            let v = read_token_account(&data).expect("read");
            assert_eq!(v.cpi_guard_locked, locked, "guard_first={guard_first}");
            assert!(v.confidential.is_some());
        }
    }
}

/// Eight knobs, one per field the reader returns; a struct would only rename them.
#[allow(clippy::too_many_arguments)]
fn build(
    owner: [u8; 32],
    delegate: Option<[u8; 32]>,
    close: Option<[u8; 32]>,
    frozen: bool,
    amount: u64,
    cap: u64,
    allow_public: bool,
    memo_first: bool,
) -> Vec<u8> {
    let mut types = vec![];
    if memo_first {
        types.push(ExtensionType::MemoTransfer);
    }
    types.push(ExtensionType::ConfidentialTransferAccount);
    let len = ExtensionType::try_calculate_account_len::<Account>(&types).expect("len");
    let mut data = vec![0u8; len];
    {
        let mut state =
            StateWithExtensionsMut::<Account>::unpack_uninitialized(&mut data).expect("unpack");
        if memo_first {
            state.init_extension::<MemoTransfer>(true).expect("memo");
        }
        let ct = state
            .init_extension::<ConfidentialTransferAccount>(true)
            .expect("ct");
        ct.approved = true.into();
        ct.allow_confidential_credits = true.into();
        ct.allow_non_confidential_credits = allow_public.into();
        ct.maximum_pending_balance_credit_counter = cap.into();
        state.base.owner = Address::new_from_array(owner);
        state.base.amount = amount;
        state.base.delegate = delegate.map(Address::new_from_array).into();
        state.base.state = if frozen {
            AccountState::Frozen
        } else {
            AccountState::Initialized
        };
        state.base.close_authority = close.map(Address::new_from_array).into();
        state.pack_base();
        state.init_account_type().expect("type");
    }
    data
}

proptest! {
    #[test]
    fn reader_agrees_with_official_unpack_on_generated_accounts(
        owner: [u8; 32],
        delegate: Option<[u8; 32]>,
        close: Option<[u8; 32]>,
        frozen: bool,
        amount: u64,
        cap: u64,
        allow_public: bool,
        memo_first: bool,
    ) {
        let data = build(owner, delegate, close, frozen, amount, cap, allow_public, memo_first);
        let v = read_token_account(&data).expect("read");
        prop_assert_eq!(v.owner, owner);
        prop_assert_eq!(v.amount, amount);
        prop_assert_eq!(v.delegate, delegate);
        prop_assert_eq!(v.close_authority, close);
        prop_assert_eq!(v.state, if frozen { AccountState::Frozen as u8 } else { AccountState::Initialized as u8 });
        let ct = v.confidential.expect("ct");
        prop_assert_eq!(ct.maximum_pending_balance_credit_counter, cap);
        prop_assert_eq!(ct.allow_non_confidential_credits, allow_public);

        // The same bytes through the official unpacker.
        let official = StateWithExtensions::<Account>::unpack(&data).expect("unpack");
        prop_assert_eq!(official.base.owner.to_bytes(), v.owner);
        prop_assert_eq!(official.base.amount, v.amount);
        prop_assert_eq!(
            Option::<Address>::from(official.base.delegate).map(|a| a.to_bytes()),
            v.delegate
        );
        prop_assert_eq!(
            Option::<Address>::from(official.base.close_authority).map(|a| a.to_bytes()),
            v.close_authority
        );
        prop_assert_eq!(official.base.state as u8, v.state);
        let official_ct = official
            .get_extension::<ConfidentialTransferAccount>()
            .expect("extension");
        prop_assert_eq!(
            u64::from(official_ct.maximum_pending_balance_credit_counter),
            ct.maximum_pending_balance_credit_counter
        );
        prop_assert_eq!(
            bool::from(official_ct.allow_non_confidential_credits),
            ct.allow_non_confidential_credits
        );
        prop_assert_eq!(
            u64::from(official_ct.pending_balance_credit_counter),
            ct.pending_balance_credit_counter
        );
    }
}
