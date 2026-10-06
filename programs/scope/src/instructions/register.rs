//! `register`: publish a recipient's meta-address under the registrant's wallet, in
//! sRFC-42 v1's entry layout, after checking B_spend has prime order (S7).

use crate::{
    address::{SYSTEM, meta_entry_pda, meta_entry_seeds},
    curve, err, pda,
};
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};
use scope_interface::{
    ScopeError,
    instruction::RegisterData,
    state::{META_ENTRY_LEN, META_SCHEME_V1, META_VERSION, MetaAddressEntry},
};

/// Accounts, in order: registrant (signer, writable), entry (writable), System program.
pub(crate) struct RegisterAccounts<'a> {
    pub(crate) registrant: &'a AccountView,
    pub(crate) entry: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for RegisterAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let [registrant, entry, system, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if !registrant.is_signer() {
            return Err(err(ScopeError::RegistrantNotSigner));
        }
        if system.address() != &SYSTEM {
            return Err(err(ScopeError::WrongSystemProgram));
        }
        Ok(Self { registrant, entry })
    }
}

/// Checks in order: data, scheme, version and flags, registrant signed, System id, entry
/// canonical and unused, B_spend of prime order.
pub(crate) fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let data = RegisterData::from_bytes(data).map_err(err)?;
    if data.scheme_id != META_SCHEME_V1 || data.version != META_VERSION || data.flags != 0 {
        return Err(err(ScopeError::UnsupportedMetaAddress));
    }
    let RegisterAccounts { registrant, entry } = RegisterAccounts::try_from(accounts)?;
    let scheme = data.scheme_id.to_le_bytes();
    let (expected, bump) = meta_entry_pda(registrant.address(), &scheme, program_id);
    if entry.address() != &expected {
        return Err(err(ScopeError::MetaAddressMismatch));
    }
    if !entry.is_data_empty() || !entry.owned_by(&SYSTEM) {
        return Err(err(ScopeError::MetaAddressInUse));
    }
    if !curve::prime_order(&data.spend) {
        return Err(err(ScopeError::InvalidSpendKey));
    }
    let bump_seed = [bump];
    pda::create(
        registrant,
        entry,
        program_id,
        META_ENTRY_LEN,
        &meta_entry_seeds(registrant.address(), &scheme, &bump_seed),
    )?;
    let record = MetaAddressEntry {
        registrant: registrant.address().to_bytes(),
        scheme_id: data.scheme_id,
        bump,
        version: data.version,
        spend: data.spend,
        scan: data.scan,
        flags: data.flags,
    };
    entry.try_borrow_mut()?.copy_from_slice(&record.to_bytes());
    Ok(())
}
