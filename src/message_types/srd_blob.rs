use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use rand::{OsRng, Rng};
use Result;

pub trait SrdBlobInterface {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized;
    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()>;
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SrdBlob {
    pub blob_type: String,
    pub data: Vec<u8>,
}

impl SrdBlob {
    pub fn new(blob_type: &str, data: &[u8]) -> SrdBlob {
        SrdBlob {
            blob_type: blob_type.to_string(),
            data: Vec::from(data),
        }
    }
}

impl SrdBlobInterface for SrdBlob {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized,
    {
        let type_size = buffer.read_u16::<LittleEndian>()?;
        let type_padding = buffer.read_u16::<LittleEndian>()?;
        let data_size = buffer.read_u16::<LittleEndian>()?;
        let data_padding = buffer.read_u16::<LittleEndian>()?;

        let length = type_size - 1;
        let mut string = vec![0u8; length as usize];
        buffer.read_exact(&mut string)?;
        buffer.read_u8()?; // null terminator
        let mut padding = vec![0u8; type_padding as usize];
        buffer.read_exact(&mut padding)?;
        let blob_type: String = string.iter().map(|c| *c as char).collect();

        let mut data = vec![0u8; data_size as usize];
        buffer.read_exact(&mut data)?;
        let mut padding = vec![0u8; data_padding as usize];
        buffer.read_exact(&mut padding)?;

        // Needed to be a multiple of 16
        let mut padding = vec![0u8; 8];
        buffer.read_exact(&mut padding)?;

        Ok(SrdBlob { blob_type, data })
    }

    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let mut rng = OsRng::new()?;

        let type_size = self.blob_type.len() + 1;
        let type_padding = 16 - (type_size % 16);
        let data_size = self.data.len();
        let data_padding = 16 - (data_size % 16);

        buffer.write_u16::<LittleEndian>(type_size as u16)?;
        buffer.write_u16::<LittleEndian>(type_padding as u16)?;
        buffer.write_u16::<LittleEndian>(data_size as u16)?;
        buffer.write_u16::<LittleEndian>(data_padding as u16)?;

        buffer.write_all(&self.blob_type.chars().map(|c| c as u8).collect::<Vec<u8>>())?;
        buffer.write_u8(0u8)?;

        let mut padding = vec![0u8; type_padding];
        rng.fill_bytes(&mut padding);
        buffer.write_all(&padding)?;

        buffer.write_all(&self.data)?;

        let mut padding = vec![0u8; data_padding];
        rng.fill_bytes(&mut padding);
        buffer.write_all(&padding)?;

        // Needed to be a multiple of 16
        let mut padding = vec![0u8; 8];
        rng.fill_bytes(&mut padding);
        buffer.write_all(&padding)?;

        Ok(())
    }
}

#[test]
fn blob_encoding() {
    let srd_blob = SrdBlob::new("Basic", &vec![0, 1, 2, 3]);

    let mut buffer: Vec<u8> = Vec::new();
    match srd_blob.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut cursor = std::io::Cursor::new(buffer);
    match SrdBlob::read_from(&mut cursor) {
        Ok(blob) => {
            assert_eq!(blob, srd_blob);
        }
        Err(_) => assert!(false),
    };
}

/*fn convert_and_pad_to_cstr(rng: &mut OsRng, str: &str) -> Result<[u8; 128]> {
    //TODO: Block large username and password
    let mut cstr = [0u8; 128];
    std::ffi::CString::new(str)?
        .as_bytes_with_nul()
        .read(&mut cstr)?;
    let index = match cstr.iter().enumerate().find(|&x| *x.1 == b'\x00') {
        None => {
            return Err(SrdError::InvalidCstr);
        }
        Some(t) => t.0,
    };
    for i in index + 1..cstr.len() {
        cstr[i] = rng.gen::<u8>();
    }
    Ok(cstr)
}

fn convert_and_unpad_from_cstr(data: &[u8]) -> Result<String> {
    let index = match data.iter().enumerate().find(|&x| *x.1 == b'\x00') {
        None => {
            return Err(SrdError::InvalidCstr);
        }
        Some(t) => t.0,
    };
    Ok(String::from_utf8(data[0..index].to_vec())?)
}
*/