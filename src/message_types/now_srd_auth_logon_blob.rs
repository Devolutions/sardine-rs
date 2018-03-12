use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::{NowAuthSrdMessage, NOW_AUTH_SRD_LOGON_BLOB_ID};

pub struct NowAuthSrdLogonBlob {
    pub packet_type: u8,
    pub flags: u8,
    pub size: u16,
    pub username: [u8; 128],
    pub password: [u8; 128],
}

impl NowAuthSrdMessage for NowAuthSrdLogonBlob {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self, std::io::Error>
    where
        Self: Sized{
        let packet_type = buffer.read_u8()?;
        let flags = buffer.read_u8()?;
        let size = buffer.read_u16::<LittleEndian>()?;

        let mut username = [0u8; 128];
        let mut password = [0u8; 128];

        buffer.read_exact(&mut username)?;
        buffer.read_exact(&mut password)?;

        Ok(NowAuthSrdLogonBlob {
            packet_type,
            flags,
            size,
            username,
            password,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        buffer.write_u8(self.packet_type)?;
        buffer.write_u8(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.size)?;
        buffer.write_all(&self.username)?;
        buffer.write_all(&self.password)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        260usize
    }

    fn get_id(&self) -> u16{
        NOW_AUTH_SRD_LOGON_BLOB_ID
    }
}