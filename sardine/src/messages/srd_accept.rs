use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use messages::{
    expand_start, srd_message::ReadMac, srd_msg_id, Message, SrdHeader,
    SrdMessage,
};
use std::io::{Read, Write};
use Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdAccept {
    pub cipher: u32,
    key_size: u16,
    reserved: u16,
    pub public_key: Vec<u8>,
    pub nonce: [u8; 32],
    pub cbt: [u8; 32],
    mac: [u8; 32],
}

impl SrdAccept {
    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    pub fn set_mac(&mut self, mac: &[u8]) {
        self.mac.clone_from_slice(mac);
    }
}

impl Message for SrdAccept {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
        where
            Self: Sized,
    {
        let cipher = reader.read_u32::<LittleEndian>()?;
        let key_size = reader.read_u16::<LittleEndian>()?;
        let reserved = reader.read_u16::<LittleEndian>()?;

        let mut public_key = vec![0u8; key_size as usize];
        reader.read_exact(&mut public_key)?;

        let mut nonce = [0u8; 32];
        reader.read_exact(&mut nonce)?;

        let mut cbt = [0u8; 32];
        reader.read_exact(&mut cbt)?;

        let mut mac = [0u8; 32];
        reader.read_mac(&mut mac)?;

        Ok(SrdAccept {
            cipher,
            key_size,
            reserved,
            public_key,
            nonce,
            cbt,
            mac,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<LittleEndian>(self.cipher)?;
        writer.write_u16::<LittleEndian>(self.key_size)?;
        writer.write_u16::<LittleEndian>(self.reserved)?;
        writer.write_all(&self.public_key)?;
        writer.write_all(&self.nonce)?;
        writer.write_all(&self.cbt)?;
        writer.write_all(&self.mac)?;
        Ok(())
    }
}

pub fn new_srd_accept_msg(
    seq_num: u8,
    use_cbt: bool,
    cipher: u32,
    key_size: u16,
    mut public_key: Vec<u8>,
    nonce: [u8; 32],
    cbt: [u8; 32],
) -> SrdMessage {
    expand_start(&mut public_key, key_size as usize);
    let hdr = SrdHeader::new(srd_msg_id::SRD_ACCEPT_MSG_ID, seq_num, use_cbt, true);
    let accept = SrdAccept {
        cipher,
        reserved: 0,
        key_size,
        public_key,
        nonce,
        cbt,
        mac: [0u8; 32],
    };

    SrdMessage::Accept(hdr, accept)
}

#[cfg(test)]
mod test {
    use messages::{new_srd_accept_msg, srd_msg_id::SRD_ACCEPT_MSG_ID, Message, SrdMessage, SRD_SIGNATURE};
    use std;

    #[test]
    fn accept_encoding() {
        let msg = new_srd_accept_msg(2, true, 0, 256, vec![0u8; 256], [0u8; 32], [0u8; 32]);
        assert_eq!(msg.msg_type(), SRD_ACCEPT_MSG_ID);

        let mut buffer: Vec<u8> = Vec::new();
        match msg.write_to(&mut buffer) {
            Ok(_) => (),
            Err(_) => assert!(false),
        };

        let mut cursor = std::io::Cursor::new(buffer.as_slice());
        match SrdMessage::read_from(&mut cursor) {
            Ok(msg_read) => {
                assert_eq!(msg_read.signature(), SRD_SIGNATURE);
                assert_eq!(msg_read, msg);
            }
            Err(_) => assert!(false),
        }
    }
}
