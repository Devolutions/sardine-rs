use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::{NowAuthSrdMessage, NOW_AUTH_SRD_CONFIRM_ID};

pub struct NowAuthSrdConfirm {
    pub packet_type: u16,
    pub flags: u16,
    pub reserved: u32,
    pub cbt: [u8; 32],
    pub mac: [u8; 32],
}

impl NowAuthSrdMessage for NowAuthSrdConfirm {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self, std::io::Error>
    where
        Self: Sized,
    {
        let packet_type = buffer.read_u16::<LittleEndian>()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let reserved = buffer.read_u32::<LittleEndian>()?;

        let mut cbt = [0u8; 32];
        let mut mac = [0u8; 32];

        buffer.read_exact(&mut cbt)?;
        buffer.read_exact(&mut mac)?;

        Ok(NowAuthSrdConfirm {
            packet_type,
            flags,
            reserved,
            cbt,
            mac,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u32::<LittleEndian>(self.reserved)?;
        buffer.write_all(&self.cbt)?;
        buffer.write_all(&self.mac)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        72usize
    }

    fn get_id(&self) -> u16 {
        NOW_AUTH_SRD_CONFIRM_ID
    }
}
