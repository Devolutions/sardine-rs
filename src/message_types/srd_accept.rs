use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::{expand_start, SrdMessage, srd_flags::{SRD_FLAG_CBT, SRD_FLAG_MAC},
                    srd_msg_id::SRD_ACCEPT_MSG_ID, SRD_SIGNATURE};
use Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdAccept {
    pub signature: u32,
    pub packet_type: u8,
    pub seq_num: u8,
    pub flags: u16,
    pub key_size: u16,
    pub reserved: u16,
    pub public_key: Vec<u8>,
    pub nonce: [u8; 32],
    pub cbt: [u8; 32],
    pub mac: [u8; 32],
}

impl SrdMessage for SrdAccept {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let signature = buffer.read_u32::<LittleEndian>()?;
        let packet_type = buffer.read_u8()?;
        let seq_num = buffer.read_u8()?;
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

        Ok(SrdAccept {
            signature,
            packet_type,
            seq_num,
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

    fn get_id(&self) -> u8 {
        SRD_ACCEPT_MSG_ID
    }

    fn get_signature(&self) -> u32 {
        self.signature
    }

    fn get_seq_num(&self) -> u8 {
        self.seq_num
    }

    fn write_inner_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u32::<LittleEndian>(self.signature)?;
        buffer.write_u8(self.packet_type)?;
        buffer.write_u8(self.seq_num)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.key_size)?;
        buffer.write_u16::<LittleEndian>(self.reserved)?;
        buffer.write_all(&self.public_key)?;
        buffer.write_all(&self.nonce)?;
        buffer.write_all(&self.cbt)?;

        Ok(())
    }

    fn get_mac(&self) -> Option<&[u8]> {
        Some(&self.mac)
    }

    fn set_mac(&mut self, mac: &[u8]) {
        self.mac.clone_from_slice(mac);
    }
}

impl SrdAccept {
    pub fn new(
        seq_num: u8,
        key_size: u16,
        mut public_key: Vec<u8>,
        nonce: [u8; 32],
        cbt_opt: Option<[u8; 32]>,
        previous_messages: &[Box<SrdMessage>],
        integrity_key: &[u8],
    ) -> Result<Self> {
        expand_start(&mut public_key, key_size as usize);
        let mut cbt = [0u8; 32];
        let mut flags = SRD_FLAG_MAC;

        match cbt_opt {
            None => (),
            Some(c) => {
                flags |= SRD_FLAG_CBT;
                cbt = c;
            }
        }

        let mut response = SrdAccept {
            signature: SRD_SIGNATURE,
            packet_type: SRD_ACCEPT_MSG_ID,
            seq_num,
            flags,
            reserved: 0,
            key_size,
            public_key,
            nonce,
            cbt,
            mac: [0u8; 32],
        };

        response.compute_mac(&previous_messages, &integrity_key)?;
        Ok(response)
    }

    pub fn has_cbt(&self) -> bool {
        self.flags & SRD_FLAG_CBT != 0
    }
}

#[cfg(test)]
mod test {
    use std;
    use message_types::{SrdAccept, SrdMessage, srd_msg_id::SRD_ACCEPT_MSG_ID, SRD_SIGNATURE};

    #[test]
    fn accept_encoding() {
        let msg = SrdAccept::new(
            2,
            256,
            vec![0u8; 256],
            [0u8; 32],
            Some([0u8; 32]),
            &Vec::new(),
            &[0u8; 32],
        ).unwrap();
        assert_eq!(msg.get_id(), SRD_ACCEPT_MSG_ID);

        let mut buffer: Vec<u8> = Vec::new();
        match msg.write_to(&mut buffer) {
            Ok(_) => (),
            Err(_) => assert!(false),
        };

        let mut cursor = std::io::Cursor::new(buffer);
        match SrdAccept::read_from(&mut cursor) {
            Ok(x) => {
                assert_eq!(x.signature, SRD_SIGNATURE);
                assert_eq!(x, msg);
            }
            Err(_) => assert!(false),
        };
    }
}
