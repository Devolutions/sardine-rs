use std::io::Read;
use std::io::Write;

use messages::{
    srd_flags::SRD_FLAG_SKIP, srd_message::ReadMac, srd_msg_id, Message, SrdHeader, SrdMessage,
};
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
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
        where
            Self: Sized,
    {
        let mut cbt = [0u8; 32];
        reader.read_exact(&mut cbt)?;

        let mut mac = [0u8; 32];
        reader.read_mac(&mut mac)?;

        Ok(SrdConfirm { cbt, mac })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.cbt)?;
        writer.write_all(&self.mac)?;
        Ok(())
    }
}

pub fn new_srd_confirm_msg(seq_num: u8, use_cbt: bool, skip_delegation: bool, cbt: [u8; 32]) -> SrdMessage {
    let mut hdr = SrdHeader::new(srd_msg_id::SRD_CONFIRM_MSG_ID, seq_num, use_cbt, true);

    if skip_delegation {
        hdr.add_flags(SRD_FLAG_SKIP);
    }

    let confirm = SrdConfirm { cbt, mac: [0u8; 32] };

    SrdMessage::Confirm(hdr, confirm)
}

#[cfg(test)]
mod test {
    use messages::{new_srd_confirm_msg, srd_msg_id::SRD_CONFIRM_MSG_ID, Message, SrdMessage, SRD_SIGNATURE};
    use std;

    #[test]
    fn confirm_encoding() {
        let msg = new_srd_confirm_msg(3, true, false, [0u8; 32]);
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
