use std;
use std::io::Read;
use std::io::Write;

use Result;
use srd_errors::SrdError;
use srd_blob::Blob;
use message_types::SrdMessage;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BasicBlob {
    username: String,
    password: String,
}

impl BasicBlob {
    pub fn new(username: &str, password: &str) -> BasicBlob {
        BasicBlob {
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}
impl Blob for BasicBlob {
    fn blob_type() -> &'static str {
        "Basic"
    }
}
impl SrdMessage for BasicBlob {
    fn read_from(buffer: &mut std::io::Cursor<&[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let mut str_buffer = Vec::new();
        buffer.read_to_end(&mut str_buffer)?;
        let full_str: String = str_buffer.iter().map(|c| *c as char).collect();

        let v: Vec<&str> = full_str.split(':').collect();

        if v.len() != 2 {
            return Err(SrdError::BlobFormatError);
        }

        Ok(BasicBlob::new(v[0], v[1]))
    }
    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let mut full_str = self.username.clone();
        full_str.push_str(":");
        full_str.push_str(&self.password);
        buffer.write_all(&full_str.chars().map(|c| c as u8).collect::<Vec<u8>>())?;
        Ok(())
    }
}
