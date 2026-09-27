//! Read-only view of a Token-2022 token account: the fields `announce` checks and
//! scan reads. Layout from spl-token-2022-interface 3.1.1.

use crate::ScopeError;

/// Token-2022 `CloseAccount` instruction data.
pub const CLOSE_ACCOUNT_INSTRUCTION: u8 = 9;
/// `AccountState::Initialized`.
pub const STATE_INITIALIZED: u8 = 1;

const BASE_LEN: usize = 165;
const ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const EXTENSION_CONFIDENTIAL_TRANSFER_ACCOUNT: u16 = 5;
const CONFIDENTIAL_TRANSFER_ACCOUNT_LEN: usize = 295;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAccountView {
    pub mint: [u8; 32],
    pub owner: [u8; 32],
    pub amount: u64,
    pub delegate: Option<[u8; 32]>,
    pub state: u8,
    pub close_authority: Option<[u8; 32]>,
    pub confidential: Option<ConfidentialView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfidentialView {
    pub approved: bool,
    pub allow_confidential_credits: bool,
    pub allow_non_confidential_credits: bool,
    pub pending_balance_credit_counter: u64,
    pub maximum_pending_balance_credit_counter: u64,
}

pub fn read_token_account(data: &[u8]) -> Result<TokenAccountView, ScopeError> {
    if data.len() <= BASE_LEN || data[BASE_LEN] != ACCOUNT_TYPE_ACCOUNT {
        return Err(ScopeError::NotTokenAccount);
    }
    Ok(TokenAccountView {
        mint: key(data, 0),
        owner: key(data, 32),
        amount: u64_le(data, 64),
        delegate: coption_key(data, 72)?,
        state: data[108],
        close_authority: coption_key(data, 129)?,
        confidential: confidential(data)?,
    })
}

fn key(data: &[u8], at: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&data[at..at + 32]);
    k
}

fn u64_le(data: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[at..at + 8]);
    u64::from_le_bytes(b)
}

fn coption_key(data: &[u8], at: usize) -> Result<Option<[u8; 32]>, ScopeError> {
    match data[at..at + 4] {
        [0, 0, 0, 0] => Ok(None),
        [1, 0, 0, 0] => Ok(Some(key(data, at + 4))),
        _ => Err(ScopeError::NotTokenAccount),
    }
}

fn confidential(data: &[u8]) -> Result<Option<ConfidentialView>, ScopeError> {
    let mut at = BASE_LEN + 1;
    while at + 4 <= data.len() {
        let ty = u16::from_le_bytes([data[at], data[at + 1]]);
        let len = u16::from_le_bytes([data[at + 2], data[at + 3]]) as usize;
        if ty == 0 {
            return Ok(None);
        }
        let value = data
            .get(at + 4..at + 4 + len)
            .ok_or(ScopeError::NotTokenAccount)?;
        if ty == EXTENSION_CONFIDENTIAL_TRANSFER_ACCOUNT {
            if len != CONFIDENTIAL_TRANSFER_ACCOUNT_LEN {
                return Err(ScopeError::NotTokenAccount);
            }
            return Ok(Some(ConfidentialView {
                approved: value[0] != 0,
                allow_confidential_credits: value[261] != 0,
                allow_non_confidential_credits: value[262] != 0,
                pending_balance_credit_counter: u64_le(value, 263),
                maximum_pending_balance_credit_counter: u64_le(value, 271),
            }));
        }
        at += 4 + len;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(owner: u8, close: Option<u8>) -> [u8; 166] {
        let mut d = [0u8; 166];
        d[32..64].fill(owner);
        d[108] = STATE_INITIALIZED;
        if let Some(c) = close {
            d[129] = 1;
            d[133..165].fill(c);
        }
        d[165] = 2;
        d
    }

    fn with_ct(base: &[u8; 166], max: u64, allow_public: bool) -> [u8; 166 + 4 + 295] {
        let mut d = [0u8; 166 + 4 + 295];
        d[..166].copy_from_slice(base);
        d[166..168].copy_from_slice(&5u16.to_le_bytes());
        d[168..170].copy_from_slice(&295u16.to_le_bytes());
        let v = 170;
        d[v] = 1;
        d[v + 261] = 1;
        d[v + 262] = allow_public as u8;
        d[v + 271..v + 279].copy_from_slice(&max.to_le_bytes());
        d
    }

    #[test]
    fn reads_owner_close_authority_and_extension() {
        let d = with_ct(&base(4, Some(8)), 1, false);
        let v = read_token_account(&d).expect("valid");
        assert_eq!(v.owner, [4; 32]);
        assert_eq!(v.close_authority, Some([8; 32]));
        assert_eq!(v.delegate, None);
        assert_eq!(v.state, STATE_INITIALIZED);
        let ct = v.confidential.expect("extension");
        assert!(ct.approved && ct.allow_confidential_credits && !ct.allow_non_confidential_credits);
        assert_eq!(ct.maximum_pending_balance_credit_counter, 1);
    }

    #[test]
    fn no_extension_reads_as_none() {
        let v = read_token_account(&base(4, None)).expect("valid");
        assert_eq!(v.confidential, None);
        assert_eq!(v.close_authority, None);
    }

    #[test]
    fn rejects_short_data_bad_type_and_bad_coption_tag() {
        assert_eq!(
            read_token_account(&[0u8; 165]),
            Err(ScopeError::NotTokenAccount)
        );
        let mut d = base(1, None);
        d[165] = 1;
        assert_eq!(read_token_account(&d), Err(ScopeError::NotTokenAccount));
        let mut d = base(1, None);
        d[72] = 2;
        assert_eq!(read_token_account(&d), Err(ScopeError::NotTokenAccount));
    }

    #[test]
    fn rejects_truncated_extension() {
        let d = with_ct(&base(4, None), 1, false);
        assert_eq!(
            read_token_account(&d[..d.len() - 1]),
            Err(ScopeError::NotTokenAccount)
        );
    }
}
