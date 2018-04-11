use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use message_types::{SrdLogonBlob, SrdMessage};
use message_types::srd_id::SRD_DELEGATE_ID;
use Result;
use srd_errors::SrdError;

pub struct SrdDelegate {
    pub packet_type: u16,
    pub flags: u16,
    pub reserved: u32,
    pub blob: SrdLogonBlob,
    pub mac: [u8; 32],
}

impl SrdMessage for SrdDelegate {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let packet_type = buffer.read_u16::<LittleEndian>()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let reserved = buffer.read_u32::<LittleEndian>()?;

        let blob = SrdLogonBlob::read_from(buffer)?;

        let mut mac = [0u8; 32];

        buffer.read_exact(&mut mac)?;

        Ok(SrdDelegate {
            packet_type,
            flags,
            reserved,
            blob,
            mac,
        })
    }

    fn write_to(&self, mut buffer: &mut Vec<u8>) -> Result<()> {
        self.write_inner_buffer(&mut buffer)?;
        buffer.write_all(&self.mac)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        40usize + self.blob.get_size()
    }

    fn get_id(&self) -> u16 {
        SRD_DELEGATE_ID
    }
}

impl SrdDelegate {
    pub fn new(blob: SrdLogonBlob, integrity_key: &[u8]) -> Result<Self> {
        let mut response = SrdDelegate {
            packet_type: SRD_DELEGATE_ID,
            flags: 0x01,
            reserved: 0,
            blob,
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

    fn write_inner_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u32::<LittleEndian>(self.reserved)?;
        self.blob.write_to(buffer)?;

        Ok(())
    }

    pub fn verify_mac(&self, integrity_key: &[u8]) -> Result<()> {
        let mut hmac = Hmac::<Sha256>::new_varkey(&integrity_key)?;

        let mut buffer = Vec::new();
        self.write_inner_buffer(&mut buffer)?;

        hmac.input(&buffer);
        match hmac.verify(&self.mac) {
            Ok(_) => Ok(()),
            Err(_) => Err(SrdError::InvalidMac),
        }
    }

    pub fn get_data(&self, iv: &[u8], key: &[u8]) -> Result<[u8; 256]> {
        Ok(self.blob.decrypt_data(iv, key)?)
    }
}
