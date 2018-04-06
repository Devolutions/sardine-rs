use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use message_types::NowAuthSrdMessage;
use message_types::expand_start;
use message_types::now_auth_srd_id::NOW_AUTH_SRD_RESPONSE_ID;
use now_auth_srd_errors::NowAuthSrdError;

use Result;

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
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
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

    fn write_to(&self, mut buffer: &mut Vec<u8>) -> Result<()> {
        self.write_inner_buffer(&mut buffer)?;
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

impl NowAuthSrdResponse {
    pub fn new(
        key_size: u16,
        mut public_key: Vec<u8>,
        nonce: [u8; 32],
        cbt_opt: Option<[u8; 32]>,
        integrity_key: &[u8],
    ) -> Result<Self> {
        expand_start(&mut public_key, key_size as usize);

        let mut flags = 0x01u16;
        let mut cbt = [0u8; 32];

        match cbt_opt {
            None => (),
            Some(c) => {
                flags = 0x03;
                cbt = c;
            }
        }

        let mut response = NowAuthSrdResponse {
            packet_type: NOW_AUTH_SRD_RESPONSE_ID,
            flags,
            reserved: 0,
            key_size,
            public_key,
            nonce,
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
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_u16::<LittleEndian>(self.reserved)?;
        buffer.write_all(&self.public_key)?;
        buffer.write_all(&self.nonce)?;
        buffer.write_all(&self.cbt)?;

        Ok(())
    }
}
