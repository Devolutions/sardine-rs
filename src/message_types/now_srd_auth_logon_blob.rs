use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crypto::aes;
use crypto::buffer;
use crypto::blockmodes::NoPadding;

use message_types::NowAuthSrdMessage;
use message_types::now_auth_srd_id::NOW_AUTH_SRD_LOGON_BLOB_ID;
use Result;

pub struct NowAuthSrdLogonBlob {
    pub packet_type: u8,
    pub flags: u8,
    pub size: u16,
    pub data: [u8; 256],
}

impl NowAuthSrdMessage for NowAuthSrdLogonBlob {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let packet_type = buffer.read_u8()?;
        let flags = buffer.read_u8()?;
        let size = buffer.read_u16::<LittleEndian>()?;

        let mut data = [0u8; 256];

        buffer.read_exact(&mut data)?;

        Ok(NowAuthSrdLogonBlob {
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

    fn get_size(&self) -> usize {
        260usize
    }

    fn get_id(&self) -> u16 {
        NOW_AUTH_SRD_LOGON_BLOB_ID
    }
}

impl NowAuthSrdLogonBlob {
    pub fn new(
        username: &[u8],
        password: &[u8],
        iv: &[u8],
        key: &[u8],
    ) -> Result<NowAuthSrdLogonBlob> {
        let mut obj = NowAuthSrdLogonBlob {
            packet_type: NOW_AUTH_SRD_LOGON_BLOB_ID as u8,
            flags: 0,
            size: 256,
            data: [0u8; 256],
        };
        obj.encrypt_data(username, password, iv, key)?;
        Ok(obj)
    }

    fn encrypt_data(
        &mut self,
        username: &[u8],
        password: &[u8],
        iv: &[u8],
        key: &[u8],
    ) -> Result<()> {
        let mut data = Vec::new();
        data.write_all(username)?;
        data.write_all(password)?;

        let mut cipher = aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, NoPadding);
        let mut read_buffer = buffer::RefReadBuffer::new(&data);
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut self.data);

        cipher.encrypt(&mut read_buffer, &mut write_buffer, false)?;
        Ok(())
    }

    pub fn decrypt_data(&self, iv: &[u8], key: &[u8]) -> Result<[u8; 256]> {
        let mut data = [0u8; 256];
        {
            let mut cipher = aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, NoPadding);
            let mut read_buffer = buffer::RefReadBuffer::new(&self.data);
            let mut write_buffer = buffer::RefWriteBuffer::new(&mut data);

            cipher.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        }
        Ok(data)
    }
}
