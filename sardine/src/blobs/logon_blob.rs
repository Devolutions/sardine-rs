use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Read;
use std::io::Write;

use crate::blobs::Blob;
use crate::messages::Message;
use crate::Result;

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
}

impl Message for LogonBlob {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
    where
        Self: Sized,
    {
        let username_length = reader.read_u16::<LittleEndian>()?;
        let password_length = reader.read_u16::<LittleEndian>()?;

        let mut username_buf = vec![0u8; username_length as usize];
        reader.read_exact(&mut username_buf)?;
        reader.read_u8()?;
        let username: String = String::from_utf8_lossy(username_buf.as_slice()).to_string();

        let mut password_buf = vec![0u8; password_length as usize];
        reader.read_exact(&mut password_buf)?;
        reader.read_u8()?;
        let password: String = String::from_utf8_lossy(password_buf.as_slice()).to_string();

        Ok(LogonBlob::new(&username, &password))
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<LittleEndian>(self.username.len() as u16)?;
        writer.write_u16::<LittleEndian>(self.password.len() as u16)?;
        writer.write_all(self.username.as_bytes())?;
        writer.write_u8(0u8)?;
        writer.write_all(self.password.as_bytes())?;
        writer.write_u8(0u8)?;
        Ok(())
    }
}