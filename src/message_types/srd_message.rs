use std;
use Result;

use srd_errors::SrdError;

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub trait SrdMessage {
    fn read_from(buffer: &mut std::io::Cursor<&[u8]>) -> Result<Self>
        where
            Self: Sized;
    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()>;
}

pub trait SrdPacket: SrdMessage {
    fn id(&self) -> u8;
    fn signature(&self) -> u32;
    fn seq_num(&self) -> u8;

    fn write_inner_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        self.write_to(buffer)
    }

    fn mac(&self) -> Option<&[u8]> {
        None
    }

    fn set_mac(&mut self, _mac: &[u8]) {}

    fn compute_mac(
        &mut self,
        previous_messages: &[Box<SrdPacket>],
        integrity_key: &[u8],
    ) -> Result<()> {
        let mut hmac = Hmac::<Sha256>::new_varkey(&integrity_key)?;

        let mut buffer = Vec::new();
        for m in previous_messages {
            m.write_inner_buffer(&mut buffer)?;
        }

        self.write_inner_buffer(&mut buffer)?;

        hmac.input(&buffer);
        let mac = hmac.result().code().to_vec();
        self.set_mac(&mac);
        Ok(())
    }

    fn verify_mac(
        &self,
        previous_messages: &[Box<SrdPacket>],
        integrity_key: &[u8],
    ) -> Result<()> {
        let message_mac = match self.mac() {
            None => {
                return Ok(());
            }
            Some(m) => m,
        };

        let mut hmac = Hmac::<Sha256>::new_varkey(&integrity_key)?;

        let mut buffer = Vec::new();
        for m in previous_messages {
            m.write_inner_buffer(&mut buffer)?;
        }

        self.write_inner_buffer(&mut buffer)?;

        hmac.input(&buffer);

        match hmac.verify(message_mac) {
            Ok(_) => Ok(()),
            Err(_) => Err(SrdError::InvalidMac),
        }
    }
}
