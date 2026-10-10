//! Payment-file parsing never panics, and amounts parse exactly.

use proptest::prelude::*;
use scope_client::input::{parse, parse_amount};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn parse_never_panics_on_arbitrary_text(text in "\\PC{0,400}", decimals in 0u8..=12) {
        let _ = parse(&text, decimals);
    }

    #[test]
    fn parse_never_panics_on_line_shaped_text(
        lines in proptest::collection::vec("[ -~]{0,70}", 0..8),
        decimals in 0u8..=12,
        crlf in any::<bool>(),
    ) {
        let text = lines.join(if crlf { "\r\n" } else { "\n" });
        let _ = parse(&text, decimals);
    }

    #[test]
    fn a_decimal_string_parses_to_the_exact_base_units(
        whole in 0u64..=281_474_976,
        frac in 0u64..1_000_000,
        decimals in 6u8..=6,
    ) {
        let text = format!("{whole}.{frac:06}");
        let units = whole * 1_000_000 + frac;
        match parse_amount(&text, decimals) {
            Ok(amount) => prop_assert_eq!(amount, units),
            Err(why) => prop_assert!(units == 0 || units >> 48 != 0, "{text}: {why}"),
        }
    }

    #[test]
    fn arbitrary_amount_text_never_panics(text in "\\PC{0,40}", decimals in 0u8..=30) {
        let _ = parse_amount(&text, decimals);
    }
}
