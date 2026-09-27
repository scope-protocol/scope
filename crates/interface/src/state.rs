use crate::ScopeError;

pub const ANNOUNCEMENT_LEN: usize = 69;
pub const ANNOUNCEMENT_DISCRIMINATOR: u8 = 1;
pub const ANNOUNCEMENT_VERSION: u8 = 1;
/// Scan filters on this byte with `memcmp`.
pub const VIEW_TAG_OFFSET: usize = 2;
const K_OFFSET: usize = 3;
const BUMP_OFFSET: usize = 4;
const EPHEMERAL_OFFSET: usize = 5;
const PAYER_OFFSET: usize = 37;

/// The announcement account written by `announce`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announcement {
    pub view_tag: u8,
    pub k: u8,
    pub bump: u8,
    pub ephemeral: [u8; 32],
    pub payer: [u8; 32],
}

impl Announcement {
    pub fn to_bytes(&self) -> [u8; ANNOUNCEMENT_LEN] {
        let mut out = [0u8; ANNOUNCEMENT_LEN];
        out[0] = ANNOUNCEMENT_DISCRIMINATOR;
        out[1] = ANNOUNCEMENT_VERSION;
        out[VIEW_TAG_OFFSET] = self.view_tag;
        out[K_OFFSET] = self.k;
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
            k: data[K_OFFSET],
            bump: data[BUMP_OFFSET],
            ephemeral,
            payer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Announcement {
        Announcement {
            view_tag: 0xab,
            k: 0,
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
        assert_eq!(bytes.len(), 69);
        assert_eq!(bytes[0], ANNOUNCEMENT_DISCRIMINATOR);
        assert_eq!(bytes[1], ANNOUNCEMENT_VERSION);
        assert_eq!(bytes[VIEW_TAG_OFFSET], 0xab);
        assert_eq!(bytes[3], 0);
        assert_eq!(bytes[4], 254);
        assert_eq!(&bytes[5..37], &[7; 32]);
        assert_eq!(&bytes[37..69], &[9; 32]);
    }

    #[test]
    fn rejects_wrong_length_and_discriminator() {
        let mut bytes = sample().to_bytes();
        assert_eq!(
            Announcement::from_bytes(&bytes[..68]),
            Err(ScopeError::NotAnnouncement)
        );
        bytes[0] = 2;
        assert_eq!(
            Announcement::from_bytes(&bytes),
            Err(ScopeError::NotAnnouncement)
        );
    }
}
