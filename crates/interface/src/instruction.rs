use crate::ScopeError;

/// First byte of every instruction.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeInstruction {
    Announce = 0,
    Reclaim = 1,
    Register = 2,
    Deregister = 3,
}

impl TryFrom<u8> for ScopeInstruction {
    type Error = ScopeError;

    fn try_from(tag: u8) -> Result<Self, ScopeError> {
        match tag {
            0 => Ok(Self::Announce),
            1 => Ok(Self::Reclaim),
            2 => Ok(Self::Register),
            3 => Ok(Self::Deregister),
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

/// `register` data after the discriminator, in sRFC-42's order: scheme id (u16 LE),
/// then the payload: version, B_spend, B_scan, flags.
pub const REGISTER_DATA_LEN: usize = 68;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterData {
    pub scheme_id: u16,
    pub version: u8,
    pub spend: [u8; 32],
    pub scan: [u8; 32],
    pub flags: u8,
}

impl RegisterData {
    /// Full instruction data, discriminator included.
    pub fn to_bytes(&self) -> [u8; 1 + REGISTER_DATA_LEN] {
        let mut out = [0u8; 1 + REGISTER_DATA_LEN];
        out[0] = ScopeInstruction::Register as u8;
        out[1..3].copy_from_slice(&self.scheme_id.to_le_bytes());
        out[3] = self.version;
        out[4..36].copy_from_slice(&self.spend);
        out[36..68].copy_from_slice(&self.scan);
        out[68] = self.flags;
        out
    }

    /// Parses the data after the discriminator; the length must be exact.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ScopeError> {
        if data.len() != REGISTER_DATA_LEN {
            return Err(ScopeError::InvalidInstructionData);
        }
        let mut spend = [0u8; 32];
        spend.copy_from_slice(&data[3..35]);
        let mut scan = [0u8; 32];
        scan.copy_from_slice(&data[35..67]);
        Ok(Self {
            scheme_id: u16::from_le_bytes([data[0], data[1]]),
            version: data[2],
            spend,
            scan,
            flags: data[67],
        })
    }
}

/// `deregister` data after the discriminator: the scheme id (u16 LE).
pub fn deregister_data(scheme_id: u16) -> [u8; 3] {
    let id = scheme_id.to_le_bytes();
    [ScopeInstruction::Deregister as u8, id[0], id[1]]
}

/// Parses `deregister` data after the discriminator.
pub fn parse_deregister(data: &[u8]) -> Result<u16, ScopeError> {
    match data {
        [lo, hi] => Ok(u16::from_le_bytes([*lo, *hi])),
        _ => Err(ScopeError::InvalidInstructionData),
    }
}

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
            Ok(ScopeInstruction::Register)
        );
        assert_eq!(
            ScopeInstruction::try_from(3),
            Ok(ScopeInstruction::Deregister)
        );
        assert_eq!(
            ScopeInstruction::try_from(4),
            Err(ScopeError::InvalidInstruction)
        );
        assert_eq!(RECLAIM_DATA, [1]);
    }

    #[test]
    fn register_round_trips_in_srfc_42_order() {
        let d = RegisterData {
            scheme_id: 0x0201,
            version: 1,
            spend: [5; 32],
            scan: [6; 32],
            flags: 0,
        };
        let bytes = d.to_bytes();
        assert_eq!(bytes.len(), 69);
        assert_eq!(&bytes[..4], &[2, 0x01, 0x02, 1]);
        assert_eq!(&bytes[4..36], &[5; 32]);
        assert_eq!(&bytes[36..68], &[6; 32]);
        assert_eq!(RegisterData::from_bytes(&bytes[1..]), Ok(d));
        assert_eq!(
            RegisterData::from_bytes(&bytes[2..]),
            Err(ScopeError::InvalidInstructionData)
        );
    }

    #[test]
    fn deregister_round_trips() {
        assert_eq!(deregister_data(1), [3, 1, 0]);
        assert_eq!(parse_deregister(&deregister_data(7)[1..]), Ok(7));
        assert_eq!(
            parse_deregister(&[1]),
            Err(ScopeError::InvalidInstructionData)
        );
    }
}
