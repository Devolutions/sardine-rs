use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use messages::{expand_start, srd_msg_id, Message, SrdHeader, SrdMessage};
use std::io::{Read, Write};
use Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdOffer {
    pub ciphers: u32,
    key_size: u16,
    pub generator: Vec<u8>,
    pub prime: Vec<u8>,
    pub public_key: Vec<u8>,
    pub nonce: [u8; 32],
}

impl SrdOffer {
    pub fn key_size(&self) -> u16 {
        self.key_size
    }
}

impl Message for SrdOffer {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
    where
        Self: Sized,
    {
        let ciphers = reader.read_u32::<LittleEndian>()?;
        let key_size = reader.read_u16::<LittleEndian>()?;

        let mut generator = vec![0u8; 2];
        let mut prime = vec![0u8; key_size as usize];
        let mut public_key = vec![0u8; key_size as usize];
        reader.read_exact(&mut generator)?;
        reader.read_exact(&mut prime)?;
        reader.read_exact(&mut public_key)?;

        let mut nonce = [0u8; 32];
        reader.read_exact(&mut nonce)?;

        Ok(SrdOffer {
            ciphers,
            key_size,
            generator,
            prime,
            public_key,
            nonce,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<LittleEndian>(self.ciphers)?;
        writer.write_u16::<LittleEndian>(self.key_size)?;
        writer.write_all(&self.generator)?;
        writer.write_all(&self.prime)?;
        writer.write_all(&self.public_key)?;
        writer.write_all(&self.nonce)?;

        Ok(())
    }
}

pub fn new_srd_offer_msg(
    seq_num: u8,
    ciphers: u32,
    key_size: u16,
    mut generator: Vec<u8>,
    mut prime: Vec<u8>,
    mut public_key: Vec<u8>,
    nonce: [u8; 32],
) -> SrdMessage {
    expand_start(&mut generator, 2);
    expand_start(&mut prime, (key_size / 8) as usize);
    expand_start(&mut public_key, (key_size / 8) as usize);

    let hdr = SrdHeader::new(srd_msg_id::SRD_OFFER_MSG_ID, seq_num, 0);
    let offer = SrdOffer {
        ciphers,
        key_size,
        generator,
        prime,
        public_key,
        nonce,
    };
    SrdMessage::Offer(hdr, offer)
}

#[cfg(test)]
mod test {
    use messages::{new_srd_offer_msg, srd_msg_id::SRD_OFFER_MSG_ID, Message, SrdMessage, SRD_SIGNATURE};
    use std;

    #[test]
    fn offer_encoding() {
        let msg = new_srd_offer_msg(1, 0, 256, vec![0, 0], vec![0u8; 256], vec![0u8; 256], [0u8; 32]);
        assert_eq!(msg.msg_type(), SRD_OFFER_MSG_ID);

        let mut buffer: Vec<u8> = Vec::new();
        match msg.write_to(&mut buffer) {
            Ok(_) => (),
            Err(_) => assert!(false),
        };

        let mut cursor = std::io::Cursor::new(buffer.as_slice());
        match SrdMessage::read_from(&mut cursor) {
            Ok(msg_read) => {
                assert_eq!(msg.signature(), SRD_SIGNATURE);
                assert_eq!(msg_read, msg);
            }
            Err(_) => assert!(false),
        }
    }
}
