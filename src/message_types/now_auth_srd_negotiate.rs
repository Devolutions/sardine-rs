use std;
use std::io::{Read, Write};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::{NowAuthSrdMessage, NOW_AUTH_SRD_NEGOTIATE_ID};

pub struct NowAuthSrdNegotiate{
    pub packet_type: u16,
    pub flags: u16,
    pub key_size: u16,
    pub reserved: u16,
}

impl NowAuthSrdMessage for NowAuthSrdNegotiate{
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self, std::io::Error>
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

    fn get_size(&self) -> usize {
        8usize
    }

    fn get_id(&self) -> u16{
        NOW_AUTH_SRD_NEGOTIATE_ID
    }
}