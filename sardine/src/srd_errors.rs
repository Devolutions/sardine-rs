use hmac::crypto_mac::InvalidKeyLength;

use std;
use std::ffi::NulError;
use std::fmt;
use std::io::Error;
use std::string::FromUtf8Error;

use chacha;
use rand;

#[derive(Debug)]
pub enum SrdError {
    Io(Error),
    Ffi(NulError),
    BadSequence,
    Crypto,
    MissingBlob,
    BlobFormatError,
    Cipher,
    Rng,
    InvalidKeySize,
    InvalidMac,
    InvalidCbt,
    InvalidCert,
    InvalidCredentials,
    InvalidCstr,
    InvalidDataLength,
    InvalidSignature,
    UnknownMsgType,
    Proto(String),
    Internal(String),
}

impl fmt::Display for SrdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &SrdError::Io(ref error) => error.fmt(f),
            &SrdError::Ffi(ref _error) => write!(f, "FFI error"),
            &SrdError::BadSequence => write!(f, "Sequence error"),
            &SrdError::Crypto => write!(f, "Cryptographic error"),
            &SrdError::MissingBlob => write!(f, "Blob error"),
            &SrdError::BlobFormatError => write!(f, "Blob format error"),
            &SrdError::Cipher => write!(f, "Cipher error"),
            &SrdError::Rng => write!(f, "RNG error"),
            &SrdError::InvalidKeySize => write!(f, "Key Size error"),
            &SrdError::InvalidMac => write!(f, "MAC error"),
            &SrdError::InvalidCbt => write!(f, "CBT error"),
            &SrdError::InvalidCert => write!(f, "Certificate error"),
            &SrdError::InvalidCredentials => write!(f, "Credentials error"),
            &SrdError::InvalidCstr => write!(f, "String encoding error"),
            &SrdError::InvalidDataLength => write!(f, "Data length error"),
            &SrdError::InvalidSignature => write!(f, "Signature error"),
            &SrdError::UnknownMsgType => write!(f, "Unknown message type"),
            &SrdError::Proto(ref desc) => write!(f, "Protocol error: {}", desc),
            &SrdError::Internal(ref desc) => write!(f, "Internal error: {}", desc),
        }
    }
}

impl std::error::Error for SrdError {}

impl From<Error> for SrdError {
    fn from(error: Error) -> SrdError {
        SrdError::Io(error)
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

impl From<chacha::Error> for SrdError {
    fn from(_error: chacha::Error) -> SrdError {
        SrdError::Crypto
    }
}

impl From<rand::Error> for SrdError {
    fn from(_error: rand::Error) -> SrdError {
        SrdError::Rng
    }
}

cfg_if! {
    if #[cfg(feature = "aes")] {
        use block_modes::{InvalidKeyIvLength, BlockModeError};
        impl From<InvalidKeyIvLength> for SrdError {
            fn from(_error: InvalidKeyIvLength) -> SrdError{
                SrdError::Crypto
            }
        }

        impl From<BlockModeError> for SrdError {
            fn from(_error: BlockModeError) -> SrdError{
                SrdError::Crypto
            }
        }
    }
}
