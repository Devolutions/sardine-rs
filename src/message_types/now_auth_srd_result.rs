use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use message_types::NowAuthSrdMessage;
use message_types::now_auth_srd_id::NOW_AUTH_SRD_RESULT_ID;
use now_auth_srd_errors::NowAuthSrdError;
use Result;

pub struct NowAuthSrdResult {
    pub packet_type: u16,
    pub flags: u16,
    pub reserved: u32,
    pub status: u32,
    pub mac: [u8; 32],
}

impl NowAuthSrdMessage for NowAuthSrdResult {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let packet_type = buffer.read_u16::<LittleEndian>()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let reserved = buffer.read_u32::<LittleEndian>()?;
        let status = buffer.read_u32::<LittleEndian>()?;

        let mut mac = [0u8; 32];
        buffer.read_exact(&mut mac)?;

        Ok(NowAuthSrdResult {
            packet_type,
            flags,
            reserved,
            status,
            mac,
        })
    }

    fn write_to(&self, mut buffer: &mut Vec<u8>) -> Result<()> {
        self.write_inner_buffer(&mut buffer)?;
        buffer.write_all(&self.mac)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        44usize
    }

    fn get_id(&self) -> u16 {
        NOW_AUTH_SRD_RESULT_ID
    }
}

impl NowAuthSrdResult {
    pub fn new(status: u32, integrity_key: &[u8]) -> Result<Self> {
        let mut response = NowAuthSrdResult {
            packet_type: NOW_AUTH_SRD_RESULT_ID,
            flags: 0x01,
            reserved: 0,
            status,
            mac: [0u8; 32],
        };

        response.compute_mac(&integrity_key)?;
        Ok(response)
    }

    fn compute_mac(&mut self, integrity_key: &[u8]) -> Result<()> {
        let mut hmac = Hmac::<Sha256>::new_varkey(&integrity_key)?;

        let mut buffer = Vec::new();
        self.write_inner_buffer(&mut buffer)?;

        hmac.input(&buffer);
        let mac = hmac.result().code().to_vec();
        self.mac.clone_from_slice(&mac);
        Ok(())
    }

    pub fn verify_mac(&self, integrity_key: &[u8]) -> Result<()> {
        let mut hmac = Hmac::<Sha256>::new_varkey(&integrity_key)?;

        let mut buffer = Vec::new();
        self.write_inner_buffer(&mut buffer)?;

        hmac.input(&buffer);
        match hmac.verify(&self.mac) {
            Ok(_) => Ok(()),
            Err(_) => Err(NowAuthSrdError::InvalidMac),
        }
    }

    fn write_inner_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u32::<LittleEndian>(self.reserved)?;
        buffer.write_u32::<LittleEndian>(self.status)?;
        Ok(())
    }
}
