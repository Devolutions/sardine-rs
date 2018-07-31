use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std;
use std::io::Read;
use std::io::Write;

use message_types::{
    srd_flags::{SRD_FLAG_CBT, SRD_FLAG_MAC}, srd_message::ReadMac, srd_msg_id::SRD_CONFIRM_MSG_ID, SrdMessage,
    SrdPacket, SRD_SIGNATURE,
};
use Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdConfirm {
    signature: u32,
    packet_type: u8,
    seq_num: u8,
    flags: u16,
    pub cbt: [u8; 32],
    mac: [u8; 32],
}

impl SrdMessage for SrdConfirm {
    fn read_from(buffer: &mut std::io::Cursor<&[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let signature = buffer.read_u32::<LittleEndian>()?;
        let packet_type = buffer.read_u8()?;
        let seq_num = buffer.read_u8()?;
        let flags = buffer.read_u16::<LittleEndian>()?;

        let mut cbt = [0u8; 32];
        buffer.read_exact(&mut cbt)?;

        let mut mac = [0u8; 32];
        buffer.read_mac(&mut mac)?;

        Ok(SrdConfirm {
            signature,
            packet_type,
            seq_num,
            flags,
            cbt,
            mac,
        })
    }

    fn write_to(&self, mut buffer: &mut Vec<u8>) -> Result<()> {
        self.write_inner_buffer(&mut buffer)?;
        buffer.write_all(&self.mac)?;
        Ok(())
    }
}

impl SrdPacket for SrdConfirm {
    fn id(&self) -> u8 {
        SRD_CONFIRM_MSG_ID
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
        buffer.write_all(&self.cbt)?;

        Ok(())
    }

    fn mac(&self) -> Option<&[u8]> {
        Some(&self.mac)
    }

    fn set_mac(&mut self, mac: &[u8]) {
        self.mac.clone_from_slice(mac);
    }
}

impl SrdConfirm {
    pub fn new(
        seq_num: u8,
        cbt_opt: Option<[u8; 32]>,
        previous_messages: &[Box<SrdPacket>],
        integrity_key: &[u8],
    ) -> Result<Self> {
        let mut cbt = [0u8; 32];
        let mut flags = SRD_FLAG_MAC;

        match cbt_opt {
            None => (),
            Some(c) => {
                flags |= SRD_FLAG_CBT;
                cbt = c;
            }
        }
        let mut response = SrdConfirm {
            signature: SRD_SIGNATURE,
            packet_type: SRD_CONFIRM_MSG_ID,
            seq_num,
            flags,
            cbt,
            mac: [0u8; 32],
        };

        response.compute_mac(&previous_messages, &integrity_key)?;
        Ok(response)
    }

    pub fn has_cbt(&self) -> bool {
        self.flags & SRD_FLAG_CBT == SRD_FLAG_CBT
    }
}

#[cfg(test)]
mod test {
    use message_types::{srd_msg_id::SRD_CONFIRM_MSG_ID, SrdConfirm, SrdMessage, SrdPacket, SRD_SIGNATURE};
    use std;

    #[test]
    fn confirm_encoding() {
        let msg = SrdConfirm::new(3, Some([0u8; 32]), &Vec::new(), &[0u8; 32]).unwrap();
        assert_eq!(msg.id(), SRD_CONFIRM_MSG_ID);

        let mut buffer: Vec<u8> = Vec::new();
        match msg.write_to(&mut buffer) {
            Ok(_) => (),
            Err(_) => assert!(false),
        };

        let mut cursor = std::io::Cursor::new(buffer.as_slice());
        match SrdConfirm::read_from(&mut cursor) {
            Ok(x) => {
                assert_eq!(x.signature, SRD_SIGNATURE);
                assert_eq!(x, msg);
            }
            Err(_) => assert!(false),
        };
    }
}
