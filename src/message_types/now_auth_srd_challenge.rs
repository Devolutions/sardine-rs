use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::NowAuthSrdMessage;
use now_auth_srd::NOW_AUTH_SRD_CHALLENGE_ID;

pub struct NowAuthSrdChallenge {
    pub packet_type: u16,
    pub flags: u16,
    pub key_size: u16,
    pub generator: [u8; 2],
    pub prime: Vec<u8>,
    pub public_key: Vec<u8>,
    pub nonce: [u8; 32],
}

impl NowAuthSrdMessage for NowAuthSrdChallenge{
    fn read_from(mut buffer: &[u8]) -> Result<Self, std::io::Error>
    where
        Self: Sized{
        let packet_type = buffer.read_u16::<LittleEndian>()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let key_size = buffer.read_u16::<LittleEndian>()?;
        let generator = [buffer.read_u8()?, buffer.read_u8()?];
        let mut prime = vec![0u8; key_size as usize];
        let mut public_key = vec![0u8; key_size as usize];
        buffer.read_exact(&mut prime)?;
        buffer.read_exact(&mut public_key)?;
        let mut nonce = [0u8; 32];
        buffer.read_exact(&mut nonce);

        Ok(NowAuthSrdChallenge {
            packet_type,
            flags,
            key_size,
            generator,
            prime,
            public_key,
            nonce,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_all(&self.generator)?;
        buffer.write_all(&self.prime)?;
        buffer.write_all(&self.public_key)?;
        buffer.write_all(&self.nonce)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        40usize + self.key_size as usize * 2
    }

    fn get_id(&self) -> u16{
        NOW_AUTH_SRD_CHALLENGE_ID
    }
}
