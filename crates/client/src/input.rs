//! The payer's input file: one `recipient,amount` row per line. `recipient` is either
//! the recipient's configured confidential token account (a plain row) or its `scope:`
//! meta-address (a stealth row); `amount` is in token units with at most the mint's
//! decimals. Blank lines and `#` comments are skipped, and a first line starting with
//! `recipient` is a header.

use solana_address::Address;
use stealth_keygen::RecipientPublicKeys;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recipient {
    Plain(Address),
    Stealth(RecipientPublicKeys),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub recipient: Recipient,
    pub amount: u64,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    #[error("line {line}: expected `recipient,amount`")]
    Shape { line: usize },
    #[error("line {line}: not an address: {value}")]
    Address { line: usize, value: String },
    #[error("line {line}: bad amount {value}: {why}")]
    Amount {
        line: usize,
        value: String,
        why: &'static str,
    },
    #[error("line {line}: bad meta-address: {why}")]
    MetaAddress { line: usize, why: String },
    #[error("no rows")]
    Empty,
}

pub fn parse(text: &str, decimals: u8) -> Result<Vec<Row>, InputError> {
    let mut rows = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let content = raw.split('#').next().unwrap_or("").trim();
        if content.is_empty() || (rows.is_empty() && content.starts_with("recipient")) {
            continue;
        }
        let (recipient, amount) = content.split_once(',').ok_or(InputError::Shape { line })?;
        let (recipient, amount) = (recipient.trim(), amount.trim());
        if amount.contains(',') {
            return Err(InputError::Shape { line });
        }
        let recipient = if recipient.starts_with("scope:") {
            RecipientPublicKeys::from_meta_address(recipient)
                .map(Recipient::Stealth)
                .map_err(|e| InputError::MetaAddress {
                    line,
                    why: format!("{e:?}"),
                })?
        } else {
            recipient
                .parse::<Address>()
                .map(Recipient::Plain)
                .map_err(|_| InputError::Address {
                    line,
                    value: recipient.into(),
                })?
        };
        let amount = parse_amount(amount, decimals).map_err(|why| InputError::Amount {
            line,
            value: amount.into(),
            why,
        })?;
        rows.push(Row { recipient, amount });
    }
    if rows.is_empty() {
        return Err(InputError::Empty);
    }
    Ok(rows)
}

/// Decimal token units to base units, exact: more fractional digits than the mint has is an error,
/// and so is more than 2^48 - 1 base units, the most one confidential transfer can move.
pub fn parse_amount(s: &str, decimals: u8) -> Result<u64, &'static str> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || (s.contains('.') && !digits(frac)) {
        return Err("not a decimal number");
    }
    if frac.len() > usize::from(decimals) {
        return Err("more decimals than the mint");
    }
    let scale = 10u64
        .checked_pow(u32::from(decimals))
        .ok_or("mint decimals too large")?;
    let whole: u64 = whole.parse().map_err(|_| "too large")?;
    let frac: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<width$}", width = usize::from(decimals))
            .parse()
            .map_err(|_| "too large")?
    };
    let amount = whole
        .checked_mul(scale)
        .and_then(|w| w.checked_add(frac))
        .ok_or("too large")?;
    if amount == 0 {
        return Err("zero");
    }
    if amount >> 48 != 0 {
        return Err("above the 48-bit confidential transfer limit");
    }
    Ok(amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_exact() {
        assert_eq!(parse_amount("1", 6), Ok(1_000_000));
        assert_eq!(parse_amount("1.5", 6), Ok(1_500_000));
        assert_eq!(parse_amount("0.000001", 6), Ok(1));
        assert_eq!(parse_amount("12.340000", 6), Ok(12_340_000));
        assert_eq!(parse_amount("7", 0), Ok(7));
    }

    #[test]
    fn amounts_reject_bad_input() {
        for bad in ["", ".", "1.", ".5", "-1", "1e3", "1,5", " 1", "0", "0.0"] {
            assert!(parse_amount(bad, 6).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_amount("0.0000001", 6),
            Err("more decimals than the mint")
        );
        assert_eq!(parse_amount("18446744073710", 6), Err("too large"));
        assert_eq!(parse_amount("281474976.710655", 6), Ok((1 << 48) - 1));
        assert_eq!(
            parse_amount("281474976.710656", 6),
            Err("above the 48-bit confidential transfer limit")
        );
    }

    #[test]
    fn parses_rows_with_header_and_comments() {
        let a = Address::new_unique();
        let b = Address::new_unique();
        let text = format!("recipient,amount\n# payroll\n{a},1.5\n\n{b} , 2 # bonus\n");
        assert_eq!(
            parse(&text, 6),
            Ok(vec![
                Row {
                    recipient: Recipient::Plain(a),
                    amount: 1_500_000
                },
                Row {
                    recipient: Recipient::Plain(b),
                    amount: 2_000_000
                },
            ])
        );
    }

    #[test]
    fn rejects_bad_rows() {
        assert_eq!(parse("", 6), Err(InputError::Empty));
        assert_eq!(parse("abc", 6), Err(InputError::Shape { line: 1 }));
        let a = Address::new_unique();
        assert_eq!(
            parse(&format!("{a},1,2"), 6),
            Err(InputError::Shape { line: 1 })
        );
        assert!(matches!(
            parse("nope,1", 6),
            Err(InputError::Address { line: 1, .. })
        ));
        assert!(matches!(
            parse("scope:1111,1", 6),
            Err(InputError::MetaAddress { line: 1, .. })
        ));
    }

    #[test]
    fn parses_stealth_rows_by_meta_address() {
        let keys = stealth_keygen::RecipientSecretKeys::from_bytes([7; 64])
            .expect("test secrets")
            .derive_public_keys();
        let a = Address::new_unique();
        let text = format!("{a},1\n{},0.25\n", keys.to_meta_address());
        assert_eq!(
            parse(&text, 6),
            Ok(vec![
                Row {
                    recipient: Recipient::Plain(a),
                    amount: 1_000_000
                },
                Row {
                    recipient: Recipient::Stealth(keys),
                    amount: 250_000
                },
            ])
        );
    }
}
