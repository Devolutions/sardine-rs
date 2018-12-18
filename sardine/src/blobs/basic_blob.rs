use std::io::Read;
use std::io::Write;

use blobs::Blob;
use messages::Message;
use srd_errors::SrdError;
use Result;

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

impl Message for BasicBlob {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
    where
        Self: Sized,
    {
        let mut str_buffer = Vec::new();
        reader.read_to_end(&mut str_buffer)?;
        let full_str = String::from_utf8_lossy(str_buffer.as_slice()).to_string();

        let v: Vec<&str> = full_str.split(':').collect();

        if v.len() != 2 {
            return Err(SrdError::BlobFormatError);
        }

        Ok(BasicBlob::new(v[0], v[1]))
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut full_str = self.username.clone();
        full_str.push_str(":");
        full_str.push_str(&self.password);
        writer.write_all(full_str.as_bytes())?;
        Ok(())
    }
}
