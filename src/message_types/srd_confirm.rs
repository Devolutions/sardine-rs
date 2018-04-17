use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::{SrdMessage, srd_flags::{SRD_FLAG_CBT, SRD_FLAG_MAC},
                    srd_msg_id::SRD_CONFIRM_MSG_ID, SRD_SIGNATURE};
use Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdConfirm {
    pub signature: u32,
    pub packet_type: u8,
    pub seq_num: u8,
    pub flags: u16,
    pub cbt: [u8; 32],
    pub mac: [u8; 32],
}

impl SrdMessage for SrdConfirm {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let signature = buffer.read_u32::<LittleEndian>()?;
        let packet_type = buffer.read_u8()?;
        let seq_num = buffer.read_u8()?;
        let flags = buffer.read_u16::<LittleEndian>()?;

        let mut cbt = [0u8; 32];
        let mut mac = [0u8; 32];

        buffer.read_exact(&mut cbt)?;
        buffer.read_exact(&mut mac)?;

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

    fn get_id(&self) -> u8 {
        SRD_CONFIRM_MSG_ID
    }

    fn write_inner_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u32::<LittleEndian>(self.signature)?;
        buffer.write_u8(self.packet_type)?;
        buffer.write_u8(self.seq_num)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
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

impl SrdConfirm {
    pub fn new(cbt_opt: Option<[u8; 32]>, integrity_key: &[u8]) -> Result<Self> {
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
            seq_num: 3,
            flags,
            cbt,
            mac: [0u8; 32],
        };

        response.compute_mac(&integrity_key)?;
        Ok(response)
    }

    pub fn has_cbt(&self) -> bool {
        self.flags & SRD_FLAG_CBT == SRD_FLAG_CBT
    }
}
