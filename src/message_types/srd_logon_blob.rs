use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};



use message_types::SrdMessage;
use message_types::srd_msg_id::SRD_LOGON_BLOB_ID;
use Result;

pub struct SrdLogonBlob {
    pub packet_type: u8,
    pub flags: u8,
    pub size: u16,
    pub data: [u8; 256],
}

impl SrdMessage for SrdLogonBlob {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let packet_type = buffer.read_u8()?;
        let flags = buffer.read_u8()?;
        let size = buffer.read_u16::<LittleEndian>()?;

        let mut data = [0u8; 256];

        buffer.read_exact(&mut data)?;

        Ok(SrdLogonBlob {
            packet_type,
            flags,
            size,
            data,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u8(self.packet_type)?;
        buffer.write_u8(self.flags)?;
        buffer.write_u16::<LittleEndian>(self.size)?;
        buffer.write_all(&self.data)?;
        Ok(())
    }

    fn get_id(&self) -> u16 {
        SRD_LOGON_BLOB_ID
    }
}

impl SrdLogonBlob {
    pub fn new(username: &[u8], password: &[u8], iv: &[u8], key: &[u8]) -> Result<SrdLogonBlob> {
        let mut obj = SrdLogonBlob {
            packet_type: SRD_LOGON_BLOB_ID as u8,
            flags: 0,
            size: 256,
            data: [0u8; 256],
        };
        obj.encrypt_data(username, password, iv, key)?;
        Ok(obj)
    }
}

