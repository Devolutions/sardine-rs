use std;
use std::io::Read;
use std::io::Write;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use Result;
use srd_blob::Blob;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LogonBlob {
    username: String,
    password: String,
}

impl LogonBlob {
    pub fn new(username: &str, password: &str) -> LogonBlob {
        LogonBlob {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    pub fn get_username(&self) -> String {
        self.username.clone()
    }

    pub fn get_password(&self) -> String {
        self.password.clone()
    }
}
impl Blob for LogonBlob {
    fn blob_type() -> &'static str {
        "Logon"
    }

    fn read_from(buffer: &mut std::io::Cursor<&[u8]>) -> Result<Self> where Self: Sized {
        let username_length = buffer.read_u16::<LittleEndian>()?;
        let password_length = buffer.read_u16::<LittleEndian>()?;

        let mut username_buf = vec![0u8; username_length as usize];
        buffer.read_exact(&mut username_buf)?;
        buffer.read_u8()?;
        let username:String = username_buf.iter().map(|c| *c as char).collect();

        let mut password_buf = vec![0u8; password_length as usize];
        buffer.read_exact(&mut password_buf)?;
        buffer.read_u8()?;
        let password:String = password_buf.iter().map(|c| *c as char).collect();

        Ok(LogonBlob::new(&username, &password))
    }
    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()> {
        buffer.write_u16::<LittleEndian>(self.username.len() as u16)?;
        buffer.write_u16::<LittleEndian>(self.password.len() as u16)?;
        buffer.write_all(&self.username.chars().map(|c| c as u8).collect::<Vec<u8>>())?;
        buffer.write_u8(0u8)?;
        buffer.write_all(&self.password.chars().map(|c| c as u8).collect::<Vec<u8>>())?;
        buffer.write_u8(0u8)?;
        Ok(())
    }
}
