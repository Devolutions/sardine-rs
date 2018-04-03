use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;

use message_types::{NowAuthSrdLogonBlob, NowAuthSrdMessage};
use message_types::now_auth_srd_id::NOW_AUTH_SRD_DELEGATE_ID;
use Result;
use now_auth_srd_errors::NowAuthSrdError;

pub struct NowAuthSrdDelegate {
    pub packet_type: u16,
    pub flags: u16,
    pub reserved: u32,
    pub blob: NowAuthSrdLogonBlob,
    pub mac: [u8; 32],
}

impl NowAuthSrdMessage for NowAuthSrdDelegate {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let packet_type = buffer.read_u16::<LittleEndian>()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let reserved = buffer.read_u32::<LittleEndian>()?;

        let blob = NowAuthSrdLogonBlob::read_from(buffer)?;

        let mut mac = [0u8; 32];

        buffer.read_exact(&mut mac)?;

        Ok(NowAuthSrdDelegate {
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
        NOW_AUTH_SRD_DELEGATE_ID
    }
}

impl NowAuthSrdDelegate {
    pub fn new(blob: NowAuthSrdLogonBlob, integrity_key: &[u8]) -> Result<Self> {
        let mut response = NowAuthSrdDelegate {
            packet_type: NOW_AUTH_SRD_DELEGATE_ID,
            flags: 0x01,
            reserved: 0,
            blob,
            mac: [0u8; 32],
        };

        response.compute_mac(&integrity_key)?;
        Ok(response)
    }

    fn compute_mac(&mut self, integrity_key: &[u8]) -> Result<()> {
        let hash = Sha256::new();
        let mut hmac = Hmac::<Sha256>::new(hash, &integrity_key);

        let mut buffer = Vec::new();
        self.write_inner_buffer(&mut buffer)?;
        hmac.input(&buffer);
        hmac.raw_result(&mut self.mac);
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
        let hash = Sha256::new();
        let mut hmac = Hmac::<Sha256>::new(hash, &integrity_key);
        let mut buffer = Vec::new();
        self.write_inner_buffer(&mut buffer)?;
        hmac.input(&buffer);

        let mut mac: [u8; 32] = [0u8; 32];
        hmac.raw_result(&mut mac);

        if mac == self.mac {
            Ok(())
        } else {
            Err(NowAuthSrdError::InvalidMac)
        }
    }

    pub fn get_data(&self, iv: &[u8], key: &[u8]) -> Result<[u8; 256]> {
        Ok(self.blob.decrypt_data(iv, key)?)
    }
}
