use std;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::NowAuthSrdMessage;

pub struct NowAuthSrdNegotiate{
    pub packet_type: u16,
    pub flags: u16,
    pub key_size: u16,
    pub reserved: u16,
}

impl NowAuthSrdMessage for NowAuthSrdNegotiate{
    fn read_from(mut buffer: &[u8]) -> Result<Self, std::io::Error>
    where
        Self: Sized{
            Ok(NowAuthSrdNegotiate {
                packet_type: buffer.read_u16::<LittleEndian>()?,
                flags: buffer.read_u16::<LittleEndian>()?,
                key_size: buffer.read_u16::<LittleEndian>()?,
                reserved: buffer.read_u16::<LittleEndian>()?,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_u16::<LittleEndian>(self.reserved)?;
        Ok(())
    }

    fn get_size(&self) -> u32 {
        8u32
    }
}