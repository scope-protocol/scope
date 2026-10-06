//! `deregister`: close the registrant's entry and return its rent to the registrant.

use crate::{address::meta_entry_address, err};
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};
use scope_interface::{ScopeError, instruction::parse_deregister, state::MetaAddressEntry};

/// Accounts, in order: registrant (signer, writable), entry (writable).
pub(crate) struct DeregisterAccounts<'a> {
    pub(crate) registrant: &'a mut AccountView,
    pub(crate) entry: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for DeregisterAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let [registrant, entry, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if !registrant.is_signer() {
            return Err(err(ScopeError::RegistrantNotSigner));
        }
        Ok(Self { registrant, entry })
    }
}

/// Checks in order: data, registrant signed, entry is ours, stored registrant is the
/// signer, entry address and scheme match.
pub(crate) fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let scheme_id = parse_deregister(data).map_err(err)?;
    let DeregisterAccounts { registrant, entry } = DeregisterAccounts::try_from(accounts)?;
    if !entry.owned_by(program_id) {
        return Err(err(ScopeError::NotMetaAddressEntry));
    }
    let record = MetaAddressEntry::from_bytes(&entry.try_borrow()?).map_err(err)?;
    if record.registrant != registrant.address().to_bytes() {
        return Err(err(ScopeError::RegistrantMismatch));
    }
    let scheme = scheme_id.to_le_bytes();
    if record.scheme_id != scheme_id
        || entry.address()
            != &meta_entry_address(registrant.address(), &scheme, record.bump, program_id)
    {
        return Err(err(ScopeError::MetaAddressMismatch));
    }
    registrant.set_lamports(
        registrant
            .lamports()
            .checked_add(entry.lamports())
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    entry.set_lamports(0);
    entry.close()
}
