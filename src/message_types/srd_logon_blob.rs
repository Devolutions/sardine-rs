use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

#[cfg(all(target_arch = "wasm32"))]
use crypto::{aes, buffer, blockmodes::NoPadding};

#[cfg(not(target_arch = "wasm32"))]
use aes_soft::{Aes256, BlockCipher, block_cipher_trait::generic_array::GenericArray};

use message_types::SrdMessage;
use message_types::srd_id::SRD_LOGON_BLOB_ID;
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

    fn get_size(&self) -> usize {
        260usize
    }

    fn get_id(&self) -> u16 {
        SRD_LOGON_BLOB_ID
    }
}

impl SrdLogonBlob {
    pub fn new(
        username: &[u8],
        password: &[u8],
        iv: &[u8],
        key: &[u8],
    ) -> Result<SrdLogonBlob> {
        let mut obj = SrdLogonBlob {
            packet_type: SRD_LOGON_BLOB_ID as u8,
            flags: 0,
            size: 256,
            data: [0u8; 256],
        };
        obj.encrypt_data(username, password, iv, key)?;
        Ok(obj)
    }

    #[cfg(all(target_arch = "wasm32"))]
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

    #[cfg(not(target_arch = "wasm32"))]
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

        // First block is IV
        result.extend_from_slice(&iv[0..16]);

        for i in 0..16 {
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

    #[cfg(all(target_arch = "wasm32"))]
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

    #[cfg(not(target_arch = "wasm32"))]
    pub fn decrypt_data(&self, iv: &[u8], key: &[u8]) -> Result<[u8; 256]> {
        let cipher = Aes256::new_varkey(key)?;

        let mut result = Vec::with_capacity(256);

        let b = GenericArray::clone_from_slice(&[0u8; 16]);
        let mut blocks1 = GenericArray::clone_from_slice(&[b; 8]);
        let mut blocks2 = GenericArray::clone_from_slice(&[b; 8]);

        for i in 0..8 {
            blocks1[i] = GenericArray::clone_from_slice(&self.data[i * 16..i * 16 + 16]);
        }
        for i in 8..16 {
            blocks2[i - 8] = GenericArray::clone_from_slice(&self.data[i * 16..i * 16 + 16]);
        }

        cipher.decrypt_blocks(&mut blocks1);
        cipher.decrypt_blocks(&mut blocks2);

        result.extend_from_slice(&xor_block(&iv[0..16], blocks1[0].as_slice()));

        for i in 1..8 {
            result.extend_from_slice(&xor_block(
                &self.data[(i - 1) * 16..(i - 1) * 16 + 16],
                blocks1[i].as_slice(),
            ));
        }
        for i in 8..16 {
            result.extend_from_slice(&xor_block(
                &self.data[(i - 1) * 16..(i - 1) * 16 + 16],
                blocks2[i - 8].as_slice(),
            ));
        }

        let mut data = [0u8; 256];
        data.clone_from_slice(&result);

        println!("{:?}", data.to_vec());

        Ok(data)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn xor_block(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }

    result
}
