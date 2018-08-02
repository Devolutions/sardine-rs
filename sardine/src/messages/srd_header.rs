use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use messages::{srd_flags::*, Message, SRD_SIGNATURE};
use std::io::{Read, Write};
use Result;
use SrdError;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdHeader {
    signature: u32,
    msg_type: u8,
    seq_num: u8,
    flags: u16,
}

impl SrdHeader {
    pub fn new(msg_type: u8, seq_num: u8, flags: u16) -> Self {
        SrdHeader {
            signature: SRD_SIGNATURE,
            msg_type,
            seq_num,
            flags,
        }
    }

    pub fn msg_type(&self) -> u8 {
        self.msg_type
    }

    pub fn signature(&self) -> u32 {
        self.signature
    }

    pub fn seq_num(&self) -> u8 {
        self.seq_num
    }

    pub fn has_cbt(&self) -> bool {
        self.flags & SRD_FLAG_CBT != 0
    }

    pub fn has_mac(&self) -> bool {
        self.flags & SRD_FLAG_MAC != 0
    }

    pub fn validate_flags(&self, mac_expected: bool) -> Result<()> {
        if !self.has_mac() && mac_expected {
            return Err(SrdError::Proto(format!(
                "SRD_FLAG_MAC must be set in message type {}",
                self.msg_type
            )));
        } else if self.has_mac() && !mac_expected {
            return Err(SrdError::Proto(format!(
                "SRD_FLAG_MAC must not be set in message type {}",
                self.msg_type
            )));
        }
        Ok(())
    }
}

impl Message for SrdHeader {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
    where
        Self: Sized,
    {
        let signature = reader.read_u32::<LittleEndian>()?;
        if signature != SRD_SIGNATURE {
            return Err(SrdError::InvalidSignature);
        }

        let msg_type = reader.read_u8()?;
        let seq_num = reader.read_u8()?;
        let flags = reader.read_u16::<LittleEndian>()?;

        Ok(SrdHeader {
            signature,
            msg_type,
            seq_num,
            flags,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<LittleEndian>(self.signature)?;
        writer.write_u8(self.msg_type)?;
        writer.write_u8(self.seq_num)?;
        writer.write_u16::<LittleEndian>(self.flags)?;
        Ok(())
    }
}
