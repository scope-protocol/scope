use proptest::prelude::*;
use scope_interface::{
    instruction::AnnounceData, state::Announcement, token_account::read_token_account,
};

proptest! {
    #[test]
    fn announcement_round_trips(view_tag: u8, bump: u8, ephemeral: [u8; 32], payer: [u8; 32]) {
        let a = Announcement { view_tag, bump, ephemeral, payer };
        prop_assert_eq!(Announcement::from_bytes(&a.to_bytes()), Ok(a));
    }

    #[test]
    fn announce_data_round_trips(ephemeral: [u8; 32], view_tag: u8) {
        let d = AnnounceData { ephemeral, view_tag };
        prop_assert_eq!(AnnounceData::from_bytes(&d.to_bytes()[1..]), Ok(d));
    }

    #[test]
    fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..700)) {
        let _ = Announcement::from_bytes(&data);
        let _ = AnnounceData::from_bytes(&data);
        let _ = read_token_account(&data);
    }

    /// Token-shaped bytes reach the extension walk, which random bytes almost never do.
    #[test]
    fn token_reader_never_panics_past_the_base(
        mut data in proptest::collection::vec(any::<u8>(), 166..700),
    ) {
        data[72..76].fill(0);
        data[129..133].fill(0);
        data[165] = 2;
        let _ = read_token_account(&data);
    }
}
