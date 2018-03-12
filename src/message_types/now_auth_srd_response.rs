use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::{NowAuthSrdMessage, NOW_AUTH_SRD_RESPONSE_ID};

pub struct NowAuthSrdResponse {
    pub packet_type: u16,
    pub flags: u16,
    pub key_size: u16,
    pub reserved: u16,
    pub public_key: Vec<u8>,
    pub nonce: [u8; 32],
    pub cbt: [u8; 32],
    pub mac: [u8; 32],
}

impl NowAuthSrdMessage for NowAuthSrdResponse {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self, std::io::Error>
    where
        Self: Sized,
    {
        let packet_type = buffer.read_u16::<LittleEndian>()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let key_size = buffer.read_u16::<LittleEndian>()?;
        let reserved = buffer.read_u16::<LittleEndian>()?;

        let mut public_key = vec![0u8; key_size as usize];
        buffer.read_exact(&mut public_key)?;

        let mut nonce = [0u8; 32];
        let mut cbt = [0u8; 32];
        let mut mac = [0u8; 32];

        buffer.read_exact(&mut nonce)?;
        buffer.read_exact(&mut cbt)?;
        buffer.read_exact(&mut mac)?;

        Ok(NowAuthSrdResponse {
            packet_type,
            flags,
            key_size,
            reserved,
            public_key,
            nonce,
            cbt,
            mac,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_u16::<LittleEndian>(self.reserved)?;
        buffer.write_all(&self.public_key)?;
        buffer.write_all(&self.nonce)?;
        buffer.write_all(&self.cbt)?;
        buffer.write_all(&self.mac)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        104usize + self.key_size as usize
    }

    fn get_id(&self) -> u16 {
        NOW_AUTH_SRD_RESPONSE_ID
    }
}
