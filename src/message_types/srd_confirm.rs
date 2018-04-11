use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use message_types::SrdMessage;
use message_types::srd_id::SRD_CONFIRM_ID;
use Result;
use srd_errors::SrdError;

pub struct SrdConfirm {
    pub packet_type: u16,
    pub flags: u16,
    pub reserved: u32,
    pub cbt: [u8; 32],
    pub mac: [u8; 32],
}

impl SrdMessage for SrdConfirm {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
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

        Ok(SrdConfirm {
            packet_type,
            flags,
            reserved,
            cbt,
            mac,
        })
    }

    fn write_to(&self, mut buffer: &mut Vec<u8>) -> Result<()> {
        self.write_inner_buffer(&mut buffer)?;
        buffer.write_all(&self.mac)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        72usize
    }

    fn get_id(&self) -> u16 {
        SRD_CONFIRM_ID
    }
}

impl SrdConfirm {
    pub fn new(cbt_opt: Option<[u8; 32]>, integrity_key: &[u8]) -> Result<Self> {
        let mut flags = 0x01u16;
        let mut cbt = [0u8; 32];

        match cbt_opt {
            None => (),
            Some(c) => {
                flags = 0x03;
                cbt = c;
            }
        }
        let mut response = SrdConfirm {
            packet_type: SRD_CONFIRM_ID,
            flags,
            reserved: 0,
            cbt,
            mac: [0u8; 32],
        };

        response.compute_mac(&integrity_key)?;
        Ok(response)
    }

    pub fn has_cbt(&self) -> bool {
        self.flags & 0x02 == 0x02
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
        buffer.write_all(&self.cbt)?;

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
}
