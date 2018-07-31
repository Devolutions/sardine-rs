use srd_errors::SrdError;
use std;
use std::io::Read;
use Result;

pub trait SrdMessage {
    fn read_from(buffer: &mut std::io::Cursor<&[u8]>) -> Result<Self>
    where
        Self: Sized;
    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()>;
}

pub trait ReadMac {
    fn read_mac(&mut self, mac: &mut [u8]) -> Result<()>;
}

impl<'a> ReadMac for std::io::Cursor<&'a [u8]> {
    fn read_mac(&mut self, mut mac: &mut [u8]) -> Result<()> {

        // The MAC field is a footer: it is ALWAYS at the very end of the message
        let mac_position = match (self.get_ref().len() as u64).checked_sub(mac.len() as u64) {
            Some(mac_position) if mac_position >= self.position() => mac_position,
            _ => {
                // Either the buffer is not long enough or not enough data is available to read.
                return Err(SrdError::InvalidDataLength);
            }
        };
        self.set_position(mac_position);
        self.read_exact(&mut mac)?;
        Ok(())
    }
}
