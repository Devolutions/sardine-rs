use std;
use std::io::Read;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::NowAuthSrdMessage;
use now_auth_srd::NOW_AUTH_SRD_CHALLENGE_ID;

pub struct NowAuthSrdChallenge {
    packet_type: u16,
    flags: u16,
    key_size: u16,
    generator: [u8; 2],
    prime: Vec<u8>,
    public_key: Vec<u8>,
    nonce: [u8; 32],
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
        /*buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_u16::<LittleEndian>(self.reserved)?;*/
        Ok(())
    }

    fn get_size(&self) -> u32 {
        40u32 + self.key_size as u32 * 2
    }

    fn get_id(&self) -> u16{
        NOW_AUTH_SRD_CHALLENGE_ID
    }
}
