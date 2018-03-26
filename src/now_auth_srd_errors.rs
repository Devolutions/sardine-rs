use std;
use std::fmt;
use std::io::Error;
use std::ffi::NulError;
use crypto::symmetriccipher::SymmetricCipherError;

#[derive(Debug)]
pub enum NowAuthSrdError {
    Io(Error),
    Crypto(SymmetricCipherError),
    Ffi(NulError),
    BadSequence,
    MissingCallback,
    InvalidKeySize,
    InvalidMac,
    InvalidCbt,
    InvalidCert,
    InvalidCstr,
}

impl fmt::Display for NowAuthSrdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &NowAuthSrdError::Io(ref error) => error.fmt(f),
            &NowAuthSrdError::Crypto(ref _error) => write!(f, "Crypto error"),
            &NowAuthSrdError::Ffi(ref _error) => write!(f, "FFI error"),
            &NowAuthSrdError::BadSequence => write!(f, "Sequence error"),
            &NowAuthSrdError::MissingCallback => write!(f, "Callback error"),
            &NowAuthSrdError::InvalidKeySize => write!(f, "Key Size error"),
            &NowAuthSrdError::InvalidMac => write!(f, "MAC error"),
            &NowAuthSrdError::InvalidCbt => write!(f, "CBT error"),
            &NowAuthSrdError::InvalidCert => write!(f, "Certificate error"),
            &NowAuthSrdError::InvalidCstr => write!(f, "String encoding error"),
        }
    }
}

impl std::error::Error for NowAuthSrdError {
    fn description(&self) -> &str {
        match *self {
            NowAuthSrdError::Io(ref error) => error.description(),
            NowAuthSrdError::Crypto(ref _error) => {
                "There was a problem while encrypting or decrypting"
            }
            NowAuthSrdError::Ffi(ref _error) => {
                "There was an error while manipulating null-terminated strings"
            }
            NowAuthSrdError::BadSequence => "Unexpected packet received",
            NowAuthSrdError::MissingCallback => "No callback specified to verify credentials",
            NowAuthSrdError::InvalidKeySize => "Key size must be 256, 512 or 1024",
            NowAuthSrdError::InvalidMac => "Message authentication code is invalid",
            NowAuthSrdError::InvalidCbt => "Channel binding token is invalid",
            NowAuthSrdError::InvalidCert => "Certificate is invalid or absent",
            NowAuthSrdError::InvalidCstr => "Username or password is not null-terminated",
        }
    }
}

impl From<Error> for NowAuthSrdError {
    fn from(error: Error) -> NowAuthSrdError {
        NowAuthSrdError::Io(error)
    }
}

impl From<SymmetricCipherError> for NowAuthSrdError {
    fn from(error: SymmetricCipherError) -> NowAuthSrdError {
        NowAuthSrdError::Crypto(error)
    }
}

impl From<NulError> for NowAuthSrdError {
    fn from(error: NulError) -> NowAuthSrdError {
        NowAuthSrdError::Ffi(error)
    }
}
