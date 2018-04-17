use std;
use std::io::{Read, Write};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::{expand_start, SrdMessage, srd_msg_id::SRD_OFFER_MSG_ID, SRD_SIGNATURE};
use Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdOffer {
    pub signature: u32,
    pub packet_type: u8,
    pub seq_num: u8,
    pub flags: u16,
    pub key_size: u16,
    pub generator: Vec<u8>,
    pub prime: Vec<u8>,
    pub public_key: Vec<u8>,
    pub nonce: [u8; 32],
}

impl SrdMessage for SrdOffer {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let signature = buffer.read_u32::<LittleEndian>()?;
        let packet_type = buffer.read_u8()?;
        let seq_num = buffer.read_u8()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let key_size = buffer.read_u16::<LittleEndian>()?;

        let mut generator = vec![0u8; 2];
        let mut prime = vec![0u8; key_size as usize];
        let mut public_key = vec![0u8; key_size as usize];
        buffer.read_exact(&mut generator)?;
        buffer.read_exact(&mut prime)?;
        buffer.read_exact(&mut public_key)?;

        let mut nonce = [0u8; 32];
        buffer.read_exact(&mut nonce)?;

        Ok(SrdOffer {
            signature,
            packet_type,
            seq_num,
            flags,
            key_size,
            generator,
            prime,
            public_key,
            nonce,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u32::<LittleEndian>(self.signature)?;
        buffer.write_u8(self.packet_type)?;
        buffer.write_u8(self.seq_num)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_all(&self.generator)?;
        buffer.write_all(&self.prime)?;
        buffer.write_all(&self.public_key)?;
        buffer.write_all(&self.nonce)?;

        Ok(())
    }

    fn get_id(&self) -> u8 {
        SRD_OFFER_MSG_ID
    }
}

impl SrdOffer {
    pub fn new(
        key_size: u16,
        mut generator: Vec<u8>,
        mut prime: Vec<u8>,
        mut public_key: Vec<u8>,
        nonce: [u8; 32],
    ) -> SrdOffer {
        expand_start(&mut generator, 2);
        expand_start(&mut prime, (key_size / 8) as usize);
        expand_start(&mut public_key, (key_size / 8) as usize);

        SrdOffer {
            signature: SRD_SIGNATURE,
            packet_type: SRD_OFFER_MSG_ID,
            seq_num: 1,
            flags: 0,
            key_size,
            generator,
            prime,
            public_key,
            nonce,
        }
    }
}
