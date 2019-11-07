use srd_errors::SrdError;

use chacha::{ChaCha, KeyStream};

cfg_if! {
    if #[cfg(feature = "aes")]{
        use aes::Aes256;
        use block_modes::{BlockMode, Cbc, block_padding::NoPadding};
    }
}

use Result;

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

#[cfg(feature = "aes")]
fn encrypt_data_aes(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(SrdError::InvalidDataLength);
    }

    let cipher = Cbc::<Aes256, NoPadding>::new_var(key, &iv[0..16])?;
    let ciphertext = cipher.encrypt_vec(data);

    Ok(ciphertext)
}

#[cfg(feature = "aes")]
fn decrypt_data_aes(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(SrdError::InvalidDataLength);
    }

    let cipher = Cbc::<Aes256, NoPadding>::new_var(key, &iv[0..16])?;
    let plaintext = cipher.decrypt_vec(data)?;

    Ok(plaintext)
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
