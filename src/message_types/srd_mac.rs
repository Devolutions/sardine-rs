use Result;
use srd_errors::SrdError;

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub trait SrdMac {
    fn write_inner_buffer(&self, buffer: &mut Vec<u8>) -> Result<()>;
    fn get_mac(&self) -> &[u8];
    fn set_mac(&mut self, mac: &[u8]);

    fn compute_mac(&mut self, integrity_key: &[u8]) -> Result<()> {
        let mut hmac = Hmac::<Sha256>::new_varkey(&integrity_key)?;

        let mut buffer = Vec::new();
        self.write_inner_buffer(&mut buffer)?;

        hmac.input(&buffer);
        let mac = hmac.result().code().to_vec();
        self.set_mac(&mac);
        Ok(())
    }

    fn verify_mac(&self, integrity_key: &[u8]) -> Result<()> {
        let mut hmac = Hmac::<Sha256>::new_varkey(&integrity_key)?;

        let mut buffer = Vec::new();
        self.write_inner_buffer(&mut buffer)?;

        hmac.input(&buffer);
        match hmac.verify(self.get_mac()) {
            Ok(_) => Ok(()),
            Err(_) => Err(SrdError::InvalidMac),
        }
    }
}
