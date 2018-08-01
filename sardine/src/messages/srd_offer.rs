use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std;
use std::io::{Read, Write};

use Result;
use messages::{expand_start, SrdMessage, SrdPacket, srd_msg_id::SRD_OFFER_MSG_ID, SRD_SIGNATURE};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdOffer {
    signature: u32,
    packet_type: u8,
    seq_num: u8,
    flags: u16,
    pub ciphers: u32,
    key_size: u16,
    pub generator: Vec<u8>,
    pub prime: Vec<u8>,
    pub public_key: Vec<u8>,
    pub nonce: [u8; 32],
}

impl SrdMessage for SrdOffer {
    fn read_from(buffer: &mut std::io::Cursor<&[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let signature = buffer.read_u32::<LittleEndian>()?;
        let packet_type = buffer.read_u8()?;
        let seq_num = buffer.read_u8()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let ciphers = buffer.read_u32::<LittleEndian>()?;
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
            ciphers,
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
        buffer.write_u32::<LittleEndian>(self.ciphers)?;
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_all(&self.generator)?;
        buffer.write_all(&self.prime)?;
        buffer.write_all(&self.public_key)?;
        buffer.write_all(&self.nonce)?;

        Ok(())
    }
}

impl SrdPacket for SrdOffer {
    fn id(&self) -> u8 {
        SRD_OFFER_MSG_ID
    }

    fn signature(&self) -> u32 {
        self.signature
    }

    fn seq_num(&self) -> u8 {
        self.seq_num
    }
}

impl SrdOffer {
    pub fn new(
        seq_num: u8,
        ciphers: u32,
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
            seq_num,
            flags: 0,
            ciphers,
            key_size,
            generator,
            prime,
            public_key,
            nonce,
        }
    }

    pub fn key_size(&self) -> u16 {
        self.key_size
    }
}

#[cfg(test)]
mod test {
    use messages::{SrdMessage, SrdOffer, SrdPacket, srd_msg_id::SRD_OFFER_MSG_ID, SRD_SIGNATURE};
    use std;

    #[test]
    fn offer_encoding() {
        let msg = SrdOffer::new(1, 0, 256, vec![0, 0], vec![0u8; 256], vec![0u8; 256], [0u8; 32]);
        assert_eq!(msg.id(), SRD_OFFER_MSG_ID);

        let mut buffer: Vec<u8> = Vec::new();
        match msg.write_to(&mut buffer) {
            Ok(_) => (),
            Err(_) => assert!(false),
        };

        let mut cursor = std::io::Cursor::new(buffer.as_slice());
        match SrdOffer::read_from(&mut cursor) {
            Ok(x) => {
                assert_eq!(x.signature, SRD_SIGNATURE);
                assert_eq!(x, msg);
            }
            Err(_) => assert!(false),
        };
    }
}
