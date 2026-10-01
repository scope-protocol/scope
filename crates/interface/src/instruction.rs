use crate::ScopeError;

/// First byte of every instruction.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeInstruction {
    Announce = 0,
    Reclaim = 1,
}

impl TryFrom<u8> for ScopeInstruction {
    type Error = ScopeError;

    fn try_from(tag: u8) -> Result<Self, ScopeError> {
        match tag {
            0 => Ok(Self::Announce),
            1 => Ok(Self::Reclaim),
            _ => Err(ScopeError::InvalidInstruction),
        }
    }
}

/// `announce` data after the discriminator: R, view tag.
pub const ANNOUNCE_DATA_LEN: usize = 33;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnounceData {
    /// R, the payer's one-time public key.
    pub ephemeral: [u8; 32],
    pub view_tag: u8,
}

impl AnnounceData {
    /// Full instruction data, discriminator included.
    pub fn to_bytes(&self) -> [u8; 1 + ANNOUNCE_DATA_LEN] {
        let mut out = [0u8; 1 + ANNOUNCE_DATA_LEN];
        out[0] = ScopeInstruction::Announce as u8;
        out[1..33].copy_from_slice(&self.ephemeral);
        out[33] = self.view_tag;
        out
    }

    /// Parses the data after the discriminator; the length must be exact.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ScopeError> {
        if data.len() != ANNOUNCE_DATA_LEN {
            return Err(ScopeError::InvalidInstructionData);
        }
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&data[..32]);
        Ok(Self {
            ephemeral,
            view_tag: data[32],
        })
    }
}

/// `reclaim` takes no data after the discriminator.
pub const RECLAIM_DATA: [u8; 1] = [ScopeInstruction::Reclaim as u8];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_round_trips() {
        let d = AnnounceData {
            ephemeral: [3; 32],
            view_tag: 0x42,
        };
        let bytes = d.to_bytes();
        assert_eq!(bytes.len(), 34);
        assert_eq!(bytes[0], ScopeInstruction::Announce as u8);
        assert_eq!(bytes[33], 0x42);
        assert_eq!(AnnounceData::from_bytes(&bytes[1..]), Ok(d));
    }

    #[test]
    fn announce_rejects_wrong_length() {
        assert_eq!(
            AnnounceData::from_bytes(&[0; 32]),
            Err(ScopeError::InvalidInstructionData)
        );
        assert_eq!(
            AnnounceData::from_bytes(&[0; 34]),
            Err(ScopeError::InvalidInstructionData)
        );
    }

    #[test]
    fn discriminators_are_stable() {
        assert_eq!(
            ScopeInstruction::try_from(0),
            Ok(ScopeInstruction::Announce)
        );
        assert_eq!(ScopeInstruction::try_from(1), Ok(ScopeInstruction::Reclaim));
        assert_eq!(
            ScopeInstruction::try_from(2),
            Err(ScopeError::InvalidInstruction)
        );
        assert_eq!(RECLAIM_DATA, [1]);
    }
}
