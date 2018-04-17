use std;
use std::fmt;
use std::io::Error;
use std::ffi::NulError;
use std::string::FromUtf8Error;
use hmac::crypto_mac::InvalidKeyLength;

#[cfg(all(target_arch = "wasm32"))]
use aes_soft;

#[cfg(not(target_arch = "wasm32"))]
use crypto::symmetriccipher::SymmetricCipherError;

#[derive(Debug)]
pub enum SrdError {
    Io(Error),
    #[cfg(not(target_arch = "wasm32"))]
    Crypto(SymmetricCipherError),
    Ffi(NulError),
    BadSequence,
    MissingBlob,
    InvalidKeySize,
    InvalidMac,
    InvalidCbt,
    InvalidCert,
    InvalidCredentials,
    InvalidCstr,
    InvalidDataLength,
}

impl fmt::Display for SrdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &SrdError::Io(ref error) => error.fmt(f),
            #[cfg(not(target_arch = "wasm32"))]
            &SrdError::Crypto(ref _error) => write!(f, "Crypto error"),
            &SrdError::Ffi(ref _error) => write!(f, "FFI error"),
            &SrdError::BadSequence => write!(f, "Sequence error"),
            &SrdError::MissingBlob => write!(f, "Blob error"),
            &SrdError::InvalidKeySize => write!(f, "Key Size error"),
            &SrdError::InvalidMac => write!(f, "MAC error"),
            &SrdError::InvalidCbt => write!(f, "CBT error"),
            &SrdError::InvalidCert => write!(f, "Certificate error"),
            &SrdError::InvalidCredentials => write!(f, "Credentials error"),
            &SrdError::InvalidCstr => write!(f, "String encoding error"),
            &SrdError::InvalidDataLength => write!(f, "Data length error"),
        }
    }
}

impl std::error::Error for SrdError {
    fn description(&self) -> &str {
        match *self {
            SrdError::Io(ref error) => error.description(),
            #[cfg(not(target_arch = "wasm32"))]
            SrdError::Crypto(ref _error) => "There was a problem while encrypting or decrypting",
            SrdError::Ffi(ref _error) => {
                "There was an error while manipulating null-terminated strings"
            }
            SrdError::BadSequence => "Unexpected packet received",
            SrdError::MissingBlob => "No blob specified",
            SrdError::InvalidKeySize => "Key size must be 256, 512 or 1024",
            SrdError::InvalidMac => "Message authentication code is invalid",
            SrdError::InvalidCbt => "Channel binding token is invalid",
            SrdError::InvalidCert => "Certificate is invalid or absent",
            SrdError::InvalidCredentials => "Received credentials are invalid!",
            SrdError::InvalidCstr => "Username or password is not null-terminated",
            SrdError::InvalidDataLength => {
                "The length of the data to be encrypted or decrypted is invalid"
            }
        }
    }
}

impl From<Error> for SrdError {
    fn from(error: Error) -> SrdError {
        SrdError::Io(error)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<SymmetricCipherError> for SrdError {
    fn from(error: SymmetricCipherError) -> SrdError {
        SrdError::Crypto(error)
    }
}

impl From<NulError> for SrdError {
    fn from(error: NulError) -> SrdError {
        SrdError::Ffi(error)
    }
}

impl From<FromUtf8Error> for SrdError {
    fn from(_error: FromUtf8Error) -> SrdError {
        SrdError::InvalidCstr
    }
}

impl From<InvalidKeyLength> for SrdError {
    fn from(_error: InvalidKeyLength) -> SrdError {
        SrdError::InvalidKeySize
    }
}

#[cfg(all(target_arch = "wasm32"))]
impl From<aes_soft::block_cipher_trait::InvalidKeyLength> for SrdError {
    fn from(_error: aes_soft::block_cipher_trait::InvalidKeyLength) -> SrdError {
        SrdError::InvalidKeySize
    }
}
