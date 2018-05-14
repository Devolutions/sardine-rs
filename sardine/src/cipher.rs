#[cfg(feature = "fips")]
use aes_frast::{aes_core, aes_with_operation_mode};

#[cfg(feature = "fips")]
use srd_errors::SrdError;

use chacha::{ChaCha, KeyStream};

use Result;

#[derive(Clone, Copy)]
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
}

#[cfg(feature = "fips")]
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

#[cfg(feature = "fips")]
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

#[cfg(not(feature = "fips"))]
fn encrypt_data_aes(_: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
    unreachable!();
}

#[cfg(not(feature = "fips"))]
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
