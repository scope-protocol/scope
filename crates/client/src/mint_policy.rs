//! Which mints SCOPE pays on (docs/payer.md, Which mints work?). Pure over the mint
//! account's data, so the payer and the recipient side apply one policy.

use solana_zk_sdk::encryption::elgamal::ElGamalPubkey;
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        account_len::try_calculate_account_len_from_mint_data,
        confidential_transfer::ConfidentialTransferMint,
        default_account_state::DefaultAccountState, pausable::PausableConfig,
    },
    state::{AccountState, Mint},
};

/// What a payment needs to know about its mint.
#[derive(Debug)]
pub struct MintPolicy {
    pub decimals: u8,
    pub auditor: Option<ElGamalPubkey>,
    /// Size of a confidential token account for this mint.
    pub space: usize,
    /// Why stealth rows cannot use this mint, if they cannot.
    pub stealth_refusal: Option<&'static str>,
}

/// Extensions that make a confidential Transfer impossible or change what it means.
/// Permanent delegate is allowed and is a trust limit (docs/privacy.md). Burn-only extensions
/// are allowed: the sweep's burn is optional and falls back to a transfer-only sweep.
const REFUSED: [(ExtensionType, &str); 3] = [
    (
        ExtensionType::NonTransferable,
        "tokens cannot be transferred",
    ),
    (
        ExtensionType::TransferFeeConfig,
        "SCOPE has no transfer-with-fee path, so a fee config is refused even at 0 bps",
    ),
    (
        ExtensionType::TransferHook,
        "SCOPE passes no hook accounts, so a hook is refused even with no program set",
    ),
];

/// Every reason the mint is refused, each naming its extension; empty when none applies.
/// A paused mint is refused through `PausableConfig`.
pub fn refusals(mint_data: &[u8]) -> Result<Vec<String>, String> {
    let state =
        StateWithExtensions::<Mint>::unpack(mint_data).map_err(|_| "not a mint".to_string())?;
    let types = state
        .get_extension_types()
        .map_err(|_| "bad extensions".to_string())?;
    let mut out: Vec<String> = REFUSED
        .iter()
        .filter(|(t, _)| types.contains(t))
        .map(|(t, why)| format!("{t:?}: {why}"))
        .collect();
    if state
        .get_extension::<PausableConfig>()
        .is_ok_and(|p| bool::from(p.paused))
    {
        out.push("PausableConfig: the mint is paused, so no transfer can land".into());
    }
    Ok(out)
}

/// The mint's payment policy, or why rows on it are refused. The caller has checked that
/// the account is owned by Token-2022.
pub fn check(mint_data: &[u8]) -> Result<MintPolicy, String> {
    let refused = refusals(mint_data)?;
    if !refused.is_empty() {
        return Err(format!("not supported: {}", refused.join("; ")));
    }
    let state = StateWithExtensions::<Mint>::unpack(mint_data).map_err(|_| "not a mint")?;
    let ext = state
        .get_extension::<ConfidentialTransferMint>()
        .map_err(|_| "confidential transfers not enabled")?;
    let auditor = ext
        .auditor_elgamal_pubkey
        .get()
        .map(|key| ElGamalPubkey::try_from(key.0.as_slice()))
        .transpose()
        .map_err(|_| "bad auditor key")?;
    // `announce` does not check approval (verification: V72), so this is the client's job.
    let frozen_by_default = state
        .get_extension::<DefaultAccountState>()
        .is_ok_and(|s| s.state == AccountState::Frozen as u8);
    let stealth_refusal = if !bool::from(ext.auto_approve_new_accounts) {
        Some("stealth rows need a mint that approves new confidential accounts itself")
    } else if frozen_by_default {
        Some("stealth rows need a mint that does not freeze new accounts")
    } else {
        None
    };
    let space = try_calculate_account_len_from_mint_data(
        mint_data,
        &[ExtensionType::ConfidentialTransferAccount],
    )
    .map_err(|_| "cannot size a confidential account")?;
    Ok(MintPolicy {
        decimals: state.base.decimals,
        auditor,
        space,
        stealth_refusal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_address::Address;
    use spl_token_2022_interface::extension::{
        BaseStateWithExtensionsMut, StateWithExtensionsMut,
        confidential_mint_burn::ConfidentialMintBurn,
        confidential_transfer_fee::ConfidentialTransferFeeConfig,
        mint_close_authority::MintCloseAuthority, non_transferable::NonTransferable,
        permanent_delegate::PermanentDelegate, permissioned_burn::PermissionedBurnConfig,
        transfer_fee::TransferFeeConfig, transfer_hook::TransferHook,
    };

    /// Builds a mint holding `types`; `fill` then sets extension fields.
    fn mint(
        types: &[ExtensionType],
        fill: impl FnOnce(&mut StateWithExtensionsMut<Mint>),
    ) -> Vec<u8> {
        let mut data =
            vec![0; ExtensionType::try_calculate_account_len::<Mint>(types).expect("len")];
        let mut state =
            StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut data).expect("unpack");
        state.base = Mint {
            is_initialized: true,
            decimals: 6,
            ..Mint::default()
        };
        state.pack_base();
        state.init_account_type().expect("account type");
        for t in types {
            match t {
                ExtensionType::ConfidentialTransferMint => {
                    state
                        .init_extension::<ConfidentialTransferMint>(true)
                        .expect("ct")
                        .auto_approve_new_accounts = true.into();
                }
                ExtensionType::NonTransferable => {
                    state.init_extension::<NonTransferable>(true).expect("nt");
                }
                ExtensionType::TransferFeeConfig => {
                    state
                        .init_extension::<TransferFeeConfig>(true)
                        .expect("fee");
                }
                ExtensionType::TransferHook => {
                    state.init_extension::<TransferHook>(true).expect("hook");
                }
                ExtensionType::PermissionedBurn => {
                    state
                        .init_extension::<PermissionedBurnConfig>(true)
                        .expect("burn");
                }
                ExtensionType::ConfidentialMintBurn => {
                    state
                        .init_extension::<ConfidentialMintBurn>(true)
                        .expect("cmb");
                }
                ExtensionType::Pausable => {
                    state.init_extension::<PausableConfig>(true).expect("pause");
                }
                ExtensionType::ConfidentialTransferFeeConfig => {
                    state
                        .init_extension::<ConfidentialTransferFeeConfig>(true)
                        .expect("ct fee");
                }
                ExtensionType::PermanentDelegate => {
                    let ext = state
                        .init_extension::<PermanentDelegate>(true)
                        .expect("delegate");
                    ext.delegate = Some(Address::new_unique()).try_into().expect("key");
                }
                ExtensionType::MintCloseAuthority => {
                    state
                        .init_extension::<MintCloseAuthority>(true)
                        .expect("close");
                }
                other => panic!("fixture lacks {other:?}"),
            }
        }
        fill(&mut state);
        data
    }

    const CT: ExtensionType = ExtensionType::ConfidentialTransferMint;

    #[test]
    fn a_plain_confidential_mint_passes() {
        let policy = check(&mint(&[CT], |_| {})).expect("allowed");
        assert_eq!(policy.decimals, 6);
        assert!(policy.stealth_refusal.is_none());
        assert!(policy.auditor.is_none());
    }

    #[test]
    fn every_refused_extension_is_refused_by_name() {
        for (extension, _) in REFUSED {
            let error = check(&mint(&[CT, extension], |_| {})).expect_err("refused");
            assert!(error.contains(&format!("{extension:?}")), "{error}");
        }
    }

    #[test]
    fn a_paused_mint_is_refused_and_an_unpaused_one_is_not() {
        let paused = mint(&[CT, ExtensionType::Pausable], |state| {
            state
                .get_extension_mut::<PausableConfig>()
                .expect("pausable")
                .paused = true.into();
        });
        let error = check(&paused).expect_err("paused");
        assert!(
            error.contains("PausableConfig") && error.contains("paused"),
            "{error}"
        );
        check(&mint(&[CT, ExtensionType::Pausable], |_| {})).expect("not paused");
    }

    #[test]
    fn a_permanent_delegate_a_close_authority_and_burn_extensions_are_allowed() {
        check(&mint(
            &[
                CT,
                ExtensionType::PermanentDelegate,
                ExtensionType::MintCloseAuthority,
                ExtensionType::PermissionedBurn,
                ExtensionType::ConfidentialMintBurn,
            ],
            |_| {},
        ))
        .expect("trust limits, not refusals");
    }

    #[test]
    fn a_pyusd_shaped_mint_is_refused_for_its_fee_and_hook() {
        let pyusd = mint(
            &[
                CT,
                ExtensionType::ConfidentialTransferFeeConfig,
                ExtensionType::TransferFeeConfig,
                ExtensionType::TransferHook,
                ExtensionType::PermanentDelegate,
                ExtensionType::MintCloseAuthority,
            ],
            |state| {
                state
                    .get_extension_mut::<ConfidentialTransferMint>()
                    .expect("ct")
                    .auto_approve_new_accounts = false.into();
            },
        );
        let error = check(&pyusd).expect_err("PYUSD cannot be paid");
        assert!(error.contains("TransferFeeConfig"), "{error}");
        assert!(error.contains("TransferHook"), "{error}");
        assert!(!error.contains("PermanentDelegate"), "{error}");
    }

    #[test]
    fn stealth_needs_auto_approval() {
        let manual = mint(&[CT], |state| {
            state
                .get_extension_mut::<ConfidentialTransferMint>()
                .expect("ct")
                .auto_approve_new_accounts = false.into();
        });
        assert!(
            check(&manual)
                .expect("plain rows fine")
                .stealth_refusal
                .is_some()
        );
    }

    #[test]
    fn a_mint_without_confidential_transfers_is_not_usable() {
        let error = check(&mint(&[], |_| {})).expect_err("no confidential transfers");
        assert!(
            error.contains("confidential transfers not enabled"),
            "{error}"
        );
    }
}
