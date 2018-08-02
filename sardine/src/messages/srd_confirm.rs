use std::io::Read;
use std::io::Write;

use messages::{
    srd_flags::{SRD_FLAG_CBT, SRD_FLAG_MAC}, SrdMessage, SrdHeader, srd_msg_id, srd_message::ReadMac, Message};
use Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdConfirm {
    pub cbt: [u8; 32],
    mac: [u8; 32],
}

impl SrdConfirm {
    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    pub fn set_mac(&mut self, mac: &[u8]) {
        self.mac.clone_from_slice(mac);
    }
}

impl Message for SrdConfirm {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> where
        Self: Sized {
        let mut cbt = [0u8; 32];
        reader.read_exact(&mut cbt)?;

        let mut mac = [0u8; 32];
        reader.read_mac(&mut mac)?;

        Ok(SrdConfirm {
            cbt,
            mac,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.cbt)?;
        writer.write_all(&self.mac)?;
        Ok(())
    }
}

pub fn new_srd_confirm_msg(seq_num: u8, cbt_opt: Option<[u8; 32]>) -> SrdMessage {
    let mut cbt = [0u8; 32];
    let mut flags = SRD_FLAG_MAC;

    match cbt_opt {
        None => (),
        Some(c) => {
            flags |= SRD_FLAG_CBT;
            cbt = c;
        }
    }
    let hdr = SrdHeader::new(srd_msg_id::SRD_CONFIRM_MSG_ID, seq_num, flags);
    let confirm = SrdConfirm {
        cbt,
        mac: [0u8; 32],
    };

    SrdMessage::Confirm(hdr, confirm)
}


#[cfg(test)]
mod test {
    use std;
    use messages::{srd_msg_id::SRD_CONFIRM_MSG_ID, Message, SrdMessage, SRD_SIGNATURE, new_srd_confirm_msg};

    #[test]
    fn confirm_encoding() {
        let msg = new_srd_confirm_msg(3, Some([0u8; 32]));
        assert_eq!(msg.msg_type(), SRD_CONFIRM_MSG_ID);

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
