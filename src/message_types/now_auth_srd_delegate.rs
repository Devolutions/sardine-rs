use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use message_types::{NowAuthSrdMessage,NowAuthSrdLogonBlob, NOW_AUTH_SRD_DELEGATE_ID};

pub struct NowAuthSrdDelegate {
    pub packet_type: u16,
    pub flags: u16,
    pub reserved: u32,
    pub blob: NowAuthSrdLogonBlob,
    pub mac: [u8; 32],
}

impl NowAuthSrdMessage for NowAuthSrdDelegate {
    fn read_from(mut buffer: &[u8]) -> Result<Self, std::io::Error>
    where
        Self: Sized {
        let packet_type = buffer.read_u16::<LittleEndian>()?;
        let flags = buffer.read_u16::<LittleEndian>()?;
        let reserved = buffer.read_u32::<LittleEndian>()?;

        let blob = NowAuthSrdLogonBlob::read_from(&mut &buffer)?;

        println!("{:?}", buffer);

        let mut mac = [0u8; 32];

        buffer.read_exact(&mut mac)?;

        Ok(NowAuthSrdDelegate {
            packet_type,
            flags,
            reserved,
            blob,
            mac,
        })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        buffer.write_u16::<LittleEndian>(self.packet_type)?;
        buffer.write_u16::<LittleEndian>(self.flags)?;
        buffer.write_u32::<LittleEndian>(self.reserved)?;
        self.blob.write_to(buffer)?;
        buffer.write_all(&self.mac)?;
        Ok(())
    }

    fn get_size(&self) -> usize {
        40usize + self.blob.get_size()
    }

    fn get_id(&self) -> u16{
        NOW_AUTH_SRD_DELEGATE_ID
    }
}
