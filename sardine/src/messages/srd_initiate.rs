use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use messages::{srd_msg_id, Message, SrdHeader, SrdMessage};
use std::io::{Read, Write};
use Result;
use SrdError;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdInitiate {
    ciphers: u32,
    key_size: u16,
    reserved: u16,
}

impl SrdInitiate {
    pub fn new(ciphers: u32, key_size: u16) -> Result<Self> {
        match key_size {
            256 | 512 | 1024 => {}
            _ => return Err(SrdError::InvalidKeySize),
        }

        Ok(SrdInitiate {
            ciphers,
            key_size,
            reserved: 0,
        })
    }
    pub fn key_size(&self) -> u16 {
        self.key_size
    }
}

impl Message for SrdInitiate {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(SrdInitiate {
            ciphers: reader.read_u32::<LittleEndian>()?,
            key_size: reader.read_u16::<LittleEndian>()?,
            reserved: reader.read_u16::<LittleEndian>()?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<LittleEndian>(self.ciphers)?;
        writer.write_u16::<LittleEndian>(self.key_size)?;
        writer.write_u16::<LittleEndian>(self.reserved)?;
        Ok(())
    }
}

pub fn new_srd_initiate_msg(seq_num: u8, ciphers: u32, key_size: u16) -> Result<SrdMessage> {
    let hdr = SrdHeader::new(srd_msg_id::SRD_INITIATE_MSG_ID, seq_num, 0);
    let initiate = SrdInitiate::new(ciphers, key_size)?;
    Ok(SrdMessage::Initiate(hdr, initiate))
}

#[cfg(test)]
mod test {
    use messages::{new_srd_initiate_msg, srd_msg_id::SRD_INITIATE_MSG_ID, Message, SrdMessage, SRD_SIGNATURE};
    use std;

    #[test]
    fn initiate_encoding() {
        let msg = new_srd_initiate_msg(0, 0, 1024).unwrap();
        assert_eq!(msg.msg_type(), SRD_INITIATE_MSG_ID);

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
