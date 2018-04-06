use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

#[cfg(not(target_arch = "wasm32"))]
use crypto::{aes, buffer, blockmodes::NoPadding};

#[cfg(all(target_arch = "wasm32"))]
use aes_soft::{Aes256, BlockCipher, block_cipher_trait::generic_array::GenericArray};

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

    #[cfg(not(target_arch = "wasm32"))]
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

    #[cfg(all(target_arch = "wasm32"))]
    fn encrypt_data(
        &mut self,
        username: &[u8],
        password: &[u8],
        iv: &[u8],
        key: &[u8],
    ) -> Result<()> {
        //  The library is really barebone, so we need to reimplement CBC
        let cipher = Aes256::new_varkey(key)?;

        let mut data = Vec::new();
        data.write_all(username)?;
        data.write_all(password)?;

        let mut result = Vec::with_capacity(256 + 16);

        // First "block is IV
        result.extend_from_slice(&iv[0..16]);

        for i in 0..256 + 16 {
            let mut b = GenericArray::clone_from_slice(&xor_block(
                &result[i * 16..i * 16 + 16],
                &data[i * 16..i * 16 + 16],
            ));
            cipher.encrypt_block(&mut b);
            result.extend_from_slice(b.as_slice());
        }

        self.data.clone_from_slice(&result[16..256 + 16]);
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
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

    #[cfg(all(target_arch = "wasm32"))]
    pub fn decrypt_data(&self, iv: &[u8], key: &[u8]) -> Result<[u8; 256]> {
        let cipher = Aes256::new_varkey(key)?;

        let mut result = Vec::with_capacity(256);

        let mut blocks =
            GenericArray::clone_from_slice(&[GenericArray::clone_from_slice(&[0u8; 16]); 16]);

        for i in 0..16 {
            blocks[i] = GenericArray::clone_from_slice(&self.data[i * 16..i * 16 + 16]);
        }

        cipher.decrypt_blocks(&mut blocks);

        result.extend_from_slice(&xor_block(&iv[0..16], blocks[0].as_slice()));

        for i in 1..16 {
            result.extend_from_slice(&xor_block(blocks[i - 1].as_slice(), blocks[i].as_slice()));
        }

        //        let mut result = Vec::with_capacity(256 + 16);
        //
        //        // First "block is IV
        //        iv[0..16].write_all(&mut result);
        //
        //        for i in 0..17 {
        //            let mut b = GenericArray::clone_from_slice(&xor_block(&result[i*16], &data[i*16..i*16+16]));
        //            cipher.encrypt_block(&mut b);
        //            b.write_all(&mut result);
        //        }
        //
        //        self.data.clone_from_slice(&result[16..256+16]);
        //        Ok(())
        //        let mut data = [0u8; 256];
        //        {
        //            let mut cipher = aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, NoPadding);
        //            let mut read_buffer = buffer::RefReadBuffer::new(&self.data);
        //            let mut write_buffer = buffer::RefWriteBuffer::new(&mut data);
        //
        //            cipher.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        //        }
        let mut data = [0u8; 256];
        data.clone_from_slice(&result);
        Ok(data)
    }
}

#[cfg(all(target_arch = "wasm32"))]
fn xor_block(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}
