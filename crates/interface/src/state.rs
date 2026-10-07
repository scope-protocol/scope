use crate::ScopeError;

pub const ANNOUNCEMENT_LEN: usize = 68;
pub const ANNOUNCEMENT_DISCRIMINATOR: u8 = 1;
pub const ANNOUNCEMENT_VERSION: u8 = 1;
/// The scanner checks this tag locally after reading the announcement's R.
pub const VIEW_TAG_OFFSET: usize = 2;
const BUMP_OFFSET: usize = 3;
const EPHEMERAL_OFFSET: usize = 4;
const PAYER_OFFSET: usize = 36;

/// The announcement account written by `announce`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announcement {
    pub view_tag: u8,
    pub bump: u8,
    /// R, the payer's one-time public key.
    pub ephemeral: [u8; 32],
    /// Receives every rent refund.
    pub payer: [u8; 32],
}

impl Announcement {
    pub fn to_bytes(&self) -> [u8; ANNOUNCEMENT_LEN] {
        let mut out = [0u8; ANNOUNCEMENT_LEN];
        out[0] = ANNOUNCEMENT_DISCRIMINATOR;
        out[1] = ANNOUNCEMENT_VERSION;
        out[VIEW_TAG_OFFSET] = self.view_tag;
        out[BUMP_OFFSET] = self.bump;
        out[EPHEMERAL_OFFSET..PAYER_OFFSET].copy_from_slice(&self.ephemeral);
        out[PAYER_OFFSET..].copy_from_slice(&self.payer);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ScopeError> {
        if data.len() != ANNOUNCEMENT_LEN
            || data[0] != ANNOUNCEMENT_DISCRIMINATOR
            || data[1] != ANNOUNCEMENT_VERSION
        {
            return Err(ScopeError::NotAnnouncement);
        }
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&data[EPHEMERAL_OFFSET..PAYER_OFFSET]);
        let mut payer = [0u8; 32];
        payer.copy_from_slice(&data[PAYER_OFFSET..]);
        Ok(Self {
            view_tag: data[VIEW_TAG_OFFSET],
            bump: data[BUMP_OFFSET],
            ephemeral,
            payer,
        })
    }
}

/// A registry entry, laid out byte for byte as sRFC-42 v1's `MetaAddressEntry`
/// (susruth/slnt a958ece, `programs/registry/src/lib.rs` 117-130), Anchor discriminator
/// included, so code that reads those entries reads ours.
pub const META_ENTRY_LEN: usize = 109;
/// `sha256("account:MetaAddressEntry")[..8]`, Anchor's account discriminator.
pub const META_ENTRY_DISCRIMINATOR: [u8; 8] = [165, 7, 241, 154, 7, 172, 74, 178];
/// The only scheme and payload version: Ed25519 B_spend, X25519 B_scan, no flags.
pub const META_SCHEME_V1: u16 = 1;
pub const META_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetaAddressEntry {
    pub registrant: [u8; 32],
    pub scheme_id: u16,
    pub bump: u8,
    pub version: u8,
    pub spend: [u8; 32],
    pub scan: [u8; 32],
    pub flags: u8,
}

impl MetaAddressEntry {
    pub fn to_bytes(&self) -> [u8; META_ENTRY_LEN] {
        let mut out = [0u8; META_ENTRY_LEN];
        out[..8].copy_from_slice(&META_ENTRY_DISCRIMINATOR);
        out[8..40].copy_from_slice(&self.registrant);
        out[40..42].copy_from_slice(&self.scheme_id.to_le_bytes());
        out[42] = self.bump;
        out[43] = self.version;
        out[44..76].copy_from_slice(&self.spend);
        out[76..108].copy_from_slice(&self.scan);
        out[108] = self.flags;
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ScopeError> {
        if data.len() != META_ENTRY_LEN || data[..8] != META_ENTRY_DISCRIMINATOR {
            return Err(ScopeError::NotMetaAddressEntry);
        }
        let mut registrant = [0u8; 32];
        registrant.copy_from_slice(&data[8..40]);
        let mut spend = [0u8; 32];
        spend.copy_from_slice(&data[44..76]);
        let mut scan = [0u8; 32];
        scan.copy_from_slice(&data[76..108]);
        Ok(Self {
            registrant,
            scheme_id: u16::from_le_bytes([data[40], data[41]]),
            bump: data[42],
            version: data[43],
            spend,
            scan,
            flags: data[108],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Announcement {
        Announcement {
            view_tag: 0xab,
            bump: 254,
            ephemeral: [7; 32],
            payer: [9; 32],
        }
    }

    #[test]
    fn round_trips() {
        let a = sample();
        assert_eq!(Announcement::from_bytes(&a.to_bytes()), Ok(a));
    }

    #[test]
    fn layout_matches_design() {
        let bytes = sample().to_bytes();
        assert_eq!(bytes.len(), 68);
        assert_eq!(bytes[0], ANNOUNCEMENT_DISCRIMINATOR);
        assert_eq!(bytes[1], ANNOUNCEMENT_VERSION);
        assert_eq!(bytes[VIEW_TAG_OFFSET], 0xab);
        assert_eq!(bytes[3], 254);
        assert_eq!(&bytes[4..36], &[7; 32]);
        assert_eq!(&bytes[36..68], &[9; 32]);
    }

    #[test]
    fn rejects_wrong_length_and_discriminator() {
        let mut bytes = sample().to_bytes();
        assert_eq!(
            Announcement::from_bytes(&bytes[..67]),
            Err(ScopeError::NotAnnouncement)
        );
        bytes[0] = 2;
        assert_eq!(
            Announcement::from_bytes(&bytes),
            Err(ScopeError::NotAnnouncement)
        );
    }

    #[test]
    fn meta_entry_round_trips_in_srfc_42_layout() {
        let e = MetaAddressEntry {
            registrant: [1; 32],
            scheme_id: 1,
            bump: 253,
            version: 1,
            spend: [2; 32],
            scan: [3; 32],
            flags: 0,
        };
        let bytes = e.to_bytes();
        assert_eq!(&bytes[..8], &META_ENTRY_DISCRIMINATOR);
        assert_eq!(&bytes[40..44], &[1, 0, 253, 1]);
        assert_eq!(MetaAddressEntry::from_bytes(&bytes), Ok(e));
        assert_eq!(
            MetaAddressEntry::from_bytes(&bytes[..108]),
            Err(ScopeError::NotMetaAddressEntry)
        );
    }
}
