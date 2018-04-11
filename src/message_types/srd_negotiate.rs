use std;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::SrdMessage;
use message_types::srd_id::SRD_NEGOTIATE_ID;
use Result;

pub struct SrdNegotiate {
    pub packet_type: u16,
    pub flags: u16,
    pub key_size: u16,
    pub reserved: u16,
}

impl SrdMessage for SrdNegotiate {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(SrdNegotiate {
            packet_type: buffer.read_u16::<LittleEndian>()?,
            flags: buffer.read_u16::<LittleEndian>()?,
            key_size: buffer.read_u16::<LittleEndian>()?,
            reserved: buffer.read_u16::<LittleEndian>()?,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_u16::<LittleEndian>(self.reserved)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        8usize
    }

    fn get_id(&self) -> u16 {
        SRD_NEGOTIATE_ID
    }
}

impl SrdNegotiate {
    pub fn new(key_size: u16) -> SrdNegotiate {
        SrdNegotiate {
            packet_type: SRD_NEGOTIATE_ID,
            flags: 0,
            key_size,
            reserved: 0,
        }
    }
}
