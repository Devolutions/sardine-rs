#[cfg(feature = "aes")]
use aes_frast::{aes_core, aes_with_operation_mode};

use srd_errors::SrdError;

use chacha::{ChaCha, KeyStream};

use Result;
use std::convert::TryFrom;

const AES256_FLAG: u32 = 0x00000001;
const CHACHA20_FLAG: u32 = 0x00000100;
const XCHACHA20_FLAG: u32 = 0x00000200;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Cipher {
    AES256,
    ChaCha20,
    XChaCha20,
}

impl Cipher {
    pub fn encrypt_data(&self, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        match self {
            &Cipher::AES256 => encrypt_data_aes(data, key, iv),
            &Cipher::ChaCha20 => encrypt_data_chacha(data, key, iv),
            &Cipher::XChaCha20 => encrypt_data_xchacha(data, key, iv),
        }
    }

    pub fn decrypt_data(&self, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        match self {
            &Cipher::AES256 => decrypt_data_aes(data, key, iv),
            &Cipher::ChaCha20 => encrypt_data_chacha(data, key, iv),
            &Cipher::XChaCha20 => encrypt_data_xchacha(data, key, iv),
        }
    }

    pub fn flag(&self) -> u32 {
        match self {
            &Cipher::AES256 => AES256_FLAG,
            &Cipher::ChaCha20 => CHACHA20_FLAG,
            &Cipher::XChaCha20 => XCHACHA20_FLAG,
        }
    }

    pub fn from_flags(flags: u32) -> Vec<Self> {
        let mut ciphers = Vec::new();
        if flags & AES256_FLAG != 0 {
            ciphers.push(Cipher::AES256)
        };
        if flags & CHACHA20_FLAG != 0 {
            ciphers.push(Cipher::ChaCha20)
        };
        if flags & XCHACHA20_FLAG != 0 {
            ciphers.push(Cipher::XChaCha20)
        };
        ciphers
    }

    pub fn best_cipher(ciphers: &[Cipher]) -> Result<Cipher> {
        if ciphers.contains(&Cipher::XChaCha20) {
            return Ok(Cipher::XChaCha20);
        };
        if ciphers.contains(&Cipher::ChaCha20) {
            return Ok(Cipher::ChaCha20);
        };
        if ciphers.contains(&Cipher::AES256) {
            return Ok(Cipher::AES256);
        };
        Err(SrdError::Cipher)
    }
}

impl From<Cipher> for u32 {
    fn from(cipher: Cipher) -> Self {
        match cipher {
            Cipher::AES256 => AES256_FLAG,
            Cipher::ChaCha20 => CHACHA20_FLAG,
            Cipher::XChaCha20 => XCHACHA20_FLAG,
        }
    }
}

impl TryFrom<u32> for Cipher {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            AES256_FLAG => Ok(Cipher::AES256),
            CHACHA20_FLAG => Ok(Cipher::ChaCha20),
            XCHACHA20_FLAG => Ok(Cipher::XChaCha20),
            _ => Err(())
        }
    }
}

#[cfg(feature = "aes")]
fn encrypt_data_aes(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(SrdError::InvalidDataLength);
    }

    let mut w_keys = vec![0u32; 60];
    let mut cipher = vec![0u8; data.len()];

    aes_core::setkey_enc_auto(&key, &mut w_keys);
    aes_with_operation_mode::cbc_enc(&data, &mut cipher, &w_keys, &iv[0..16]);

    Ok(cipher)
}

#[cfg(feature = "aes")]
fn decrypt_data_aes(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(SrdError::InvalidDataLength);
    }

    let mut w_keys = vec![0u32; 60];
    let mut cipher = vec![0u8; data.len()];

    aes_core::setkey_dec_auto(&key, &mut w_keys);
    aes_with_operation_mode::cbc_dec(&data, &mut cipher, &w_keys, &iv[0..16]);

    Ok(cipher)
}

#[cfg(not(feature = "aes"))]
fn encrypt_data_aes(_: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
    unreachable!();
}

#[cfg(not(feature = "aes"))]
fn decrypt_data_aes(_: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
    unreachable!();
}

fn encrypt_data_chacha(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut key_ref = [0u8; 32];
    key_ref.copy_from_slice(key);

    let mut iv_ref = [0u8; 8];
    iv_ref.copy_from_slice(&iv[0..8]);

    let mut stream = ChaCha::new_chacha20(&key_ref, &iv_ref);
    let mut buffer = data.to_vec();

    stream.xor_read(&mut buffer)?;
    Ok(buffer)
}

fn encrypt_data_xchacha(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut key_ref = [0u8; 32];
    key_ref.copy_from_slice(key);

    let mut iv_ref = [0u8; 24];
    iv_ref.copy_from_slice(&iv[0..24]);

    let mut stream = ChaCha::new_xchacha20(&key_ref, &iv_ref);
    let mut buffer = data.to_vec();

    stream.xor_read(&mut buffer)?;
    Ok(buffer)
}
