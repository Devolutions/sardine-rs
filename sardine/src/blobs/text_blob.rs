use std::io::Read;
use std::io::Write;

use blobs::Blob;
use messages::Message;
use srd_errors::SrdError;
use Result;
use std::string::ToString;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TextBlob {
    text: String,
}

impl TextBlob {
    pub fn new(text: &str) -> Self {
        TextBlob {
            text: text.to_string(),
        }
    }
}
impl Blob for TextBlob {
    fn blob_type() -> &'static str {
        "Text"
    }
}

impl Message for TextBlob {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
        where
            Self: Sized,
    {
        let mut str_buffer = Vec::new();
        reader.read_to_end(&mut str_buffer)?;
        let full_str = String::from_utf8_lossy(str_buffer.as_slice()).to_string();

        Ok(TextBlob::new(&full_str))
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.text.as_bytes())?;
        Ok(())
    }
}
