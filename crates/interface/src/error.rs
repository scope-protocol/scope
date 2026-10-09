/// Program errors, surfaced as `Custom(code)`. Codes are append-only.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeError {
    InvalidInstruction = 0,
    InvalidInstructionData = 1,
    PayerNotSigner = 2,
    WrongSystemProgram = 3,
    WrongTokenProgram = 4,
    TokenAccountAddressMismatch = 5,
    NotTokenAccount = 6,
    TokenAccountNotInitialized = 7,
    CloseAuthorityMismatch = 8,
    OwnerNotHandedOver = 9,
    DelegateSet = 10,
    MissingConfidentialExtension = 11,
    CreditCapNotOne = 12,
    PublicCreditsEnabled = 13,
    AnnouncementAddressMismatch = 14,
    AnnouncementInUse = 15,
    NotAnnouncement = 16,
    PayerMismatch = 17,
    RegistrantNotSigner = 18,
    UnsupportedMetaAddress = 19,
    MetaAddressMismatch = 20,
    MetaAddressInUse = 21,
    InvalidSpendKey = 22,
    NotMetaAddressEntry = 23,
    RegistrantMismatch = 24,
    CpiGuardEnabled = 25,
}

const ALL: [ScopeError; 26] = [
    ScopeError::InvalidInstruction,
    ScopeError::InvalidInstructionData,
    ScopeError::PayerNotSigner,
    ScopeError::WrongSystemProgram,
    ScopeError::WrongTokenProgram,
    ScopeError::TokenAccountAddressMismatch,
    ScopeError::NotTokenAccount,
    ScopeError::TokenAccountNotInitialized,
    ScopeError::CloseAuthorityMismatch,
    ScopeError::OwnerNotHandedOver,
    ScopeError::DelegateSet,
    ScopeError::MissingConfidentialExtension,
    ScopeError::CreditCapNotOne,
    ScopeError::PublicCreditsEnabled,
    ScopeError::AnnouncementAddressMismatch,
    ScopeError::AnnouncementInUse,
    ScopeError::NotAnnouncement,
    ScopeError::PayerMismatch,
    ScopeError::RegistrantNotSigner,
    ScopeError::UnsupportedMetaAddress,
    ScopeError::MetaAddressMismatch,
    ScopeError::MetaAddressInUse,
    ScopeError::InvalidSpendKey,
    ScopeError::NotMetaAddressEntry,
    ScopeError::RegistrantMismatch,
    ScopeError::CpiGuardEnabled,
];

impl ScopeError {
    pub const fn code(self) -> u32 {
        self as u32
    }

    pub fn from_code(code: u32) -> Option<Self> {
        ALL.get(code as usize).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_positions_and_round_trip() {
        for (i, e) in ALL.iter().enumerate() {
            assert_eq!(e.code(), i as u32);
            assert_eq!(ScopeError::from_code(i as u32), Some(*e));
        }
        assert_eq!(ScopeError::from_code(ALL.len() as u32), None);
    }
}
