use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std;
use std::io::{Read, Write};

use cipher::Cipher;
use messages::{
    srd_flags::SRD_FLAG_MAC, srd_message::ReadMac, srd_msg_id::SRD_DELEGATE_MSG_ID, SrdMessage, SrdPacket,
    SRD_SIGNATURE,
};
use blobs::SrdBlob;
use Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdDelegate {
    signature: u32,
    packet_type: u8,
    seq_num: u8,
    flags: u16,
    pub size: u32,
    pub encrypted_blob: Vec<u8>,
    mac: [u8; 32],
}

impl SrdMessage for SrdDelegate {
    fn read_from(buffer: &mut std::io::Cursor<&[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let signature = buffer.read_u32::<LittleEndian>()?;
        let packet_type = buffer.read_u8()?;
        let seq_num = buffer.read_u8()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let size = buffer.read_u32::<LittleEndian>()?;

        let mut blob = vec![0u8; size as usize];
        buffer.read_exact(&mut blob)?;

        let mut mac = [0u8; 32];
        buffer.read_mac(&mut mac)?;

        Ok(SrdDelegate {
            signature,
            packet_type,
            seq_num,
            flags,
            size,
            encrypted_blob: blob,
            mac,
        })
    }

    fn write_to(&self, mut buffer: &mut Vec<u8>) -> Result<()> {
        self.write_inner_buffer(&mut buffer)?;
        buffer.write_all(&self.mac)?;
        Ok(())
    }
}

impl SrdPacket for SrdDelegate {
    fn id(&self) -> u8 {
        SRD_DELEGATE_MSG_ID
    }

    fn signature(&self) -> u32 {
        self.signature
    }

    fn seq_num(&self) -> u8 {
        self.seq_num
    }

    fn write_inner_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u32::<LittleEndian>(self.signature)?;
        buffer.write_u8(self.packet_type)?;
        buffer.write_u8(self.seq_num)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u32::<LittleEndian>(self.size)?;
        buffer.write_all(&self.encrypted_blob)?;
        Ok(())
    }

    fn mac(&self) -> Option<&[u8]> {
        Some(&self.mac)
    }

    fn set_mac(&mut self, mac: &[u8]) {
        self.mac.clone_from_slice(mac);
    }
}

impl SrdDelegate {
    pub fn new(
        seq_num: u8,
        srd_blob: &SrdBlob,
        previous_messages: &[Box<SrdPacket>],
        cipher: Cipher,
        integrity_key: &[u8],
        delegation_key: &[u8],
        iv: &[u8],
    ) -> Result<Self> {
        let mut v_blob = Vec::new();
        srd_blob.write_to(&mut v_blob)?;
        let encrypted_blob = cipher.encrypt_data(&v_blob, delegation_key, iv)?;

        let mut response = SrdDelegate {
            signature: SRD_SIGNATURE,
            packet_type: SRD_DELEGATE_MSG_ID,
            seq_num,
            flags: SRD_FLAG_MAC,
            size: (encrypted_blob.len() as u32),
            encrypted_blob,
            mac: [0u8; 32],
        };

        response.compute_mac(&previous_messages, &integrity_key)?;
        Ok(response)
    }

    pub fn get_data(&self, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<SrdBlob> {
        let buffer = cipher.decrypt_data(&self.encrypted_blob, key, iv)?;

        let mut cursor = std::io::Cursor::new(buffer.as_slice());
        let srd_blob = SrdBlob::read_from(&mut cursor)?;
        Ok(srd_blob)
    }
}

//#[cfg(test)]
//mod test {
//    use std;
//    use message_types::{SRD_SIGNATURE, SrdDelegate, SrdMessage, srd_msg_id::SRD_DELEGATE_MSG_ID};
//
//    #[test]
//    fn delegate_encoding() {
//        let blob = SrdLogonBlob {
//            packet_type: 1,
//            flags: 0,
//            size: 256,
//            data: [0u8; 256],
//        };
//
//        let msg = SrdDelegate::new()
//        {
//            packet_type: 5,
//            flags: 0,
//            reserved: 0,
//            blob,
//            mac: [0u8; 32],
//        };
//
//        assert_eq!(msg.blob.get_id(), SRD_LOGON_BLOB_ID);
//        assert_eq!(msg.get_id(), SRD_DELEGATE_ID);
//
//        let mut buffer: Vec<u8> = Vec::new();
//        match msg.write_to(&mut buffer) {
//            Ok(_) => (),
//            Err(_) => assert!(false),
//        };
//
//        let mut expected = vec![5, 0, 0, 0, 0, 0, 0, 0];
//        expected.append(&mut vec![1, 0, 0, 1]);
//        expected.append(&mut vec![0u8; 256]);
//        expected.append(&mut vec![0u8; 32]);
//
//        assert_eq!(buffer, expected);
//        assert_eq!(buffer.len(), msg.get_size());
//
//        let mut cursor = std::io::Cursor::new(buffer);
//
//        match SrdDelegate::read_from(&mut cursor) {
//            Ok(x) => {
//                assert_eq!(x.packet_type, 5);
//                assert_eq!(x.flags, 0);
//                assert_eq!(x.reserved, 0);
//                assert_eq!(x.blob.packet_type, 1);
//                assert_eq!(x.blob.size, 256);
//                assert_eq!(x.blob.data.to_vec(), vec![0u8; 256]);
//                assert_eq!(x.mac, [0u8; 32]);
//            }
//            Err(_) => assert!(false),
//        };
//    }
//}
