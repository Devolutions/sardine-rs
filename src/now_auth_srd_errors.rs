use std;
use std::fmt;

#[derive(Debug)]
pub enum NowAuthSrdError {
    Io(std::io::Error),
    BadSequence,
    MissingCallback,
    InvalidKeySize,
    InvalidMac,
    InvalidCbt,
    InvalidCert,
}

impl fmt::Display for NowAuthSrdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &NowAuthSrdError::Io(ref error) => error.fmt(f),
            &NowAuthSrdError::BadSequence => write!(f, "Sequence error"),
            &NowAuthSrdError::MissingCallback => write!(f, "Callback error"),
            &NowAuthSrdError::InvalidKeySize => write!(f, "Key Size error"),
            &NowAuthSrdError::InvalidMac => write!(f, "MAC error"),
            &NowAuthSrdError::InvalidCbt => write!(f, "CBT error"),
            &NowAuthSrdError::InvalidCert => write!(f, "Certificate error"),
        }
    }
}

impl std::error::Error for NowAuthSrdError {
    fn description(&self) -> &str {
        match *self {
            NowAuthSrdError::Io(ref error) => error.description(),
            NowAuthSrdError::BadSequence => "Unexpected packet received",
            NowAuthSrdError::MissingCallback => "No callback specified to verify credentials",
            NowAuthSrdError::InvalidKeySize => "Key size must be 256, 512 or 1024",
            NowAuthSrdError::InvalidMac => "Message authentication code is invalid",
            NowAuthSrdError::InvalidCbt => "Channel binding token is invalid",
            NowAuthSrdError::InvalidCert => "Certificate is invalid or absent",
        }
    }
}

impl From<std::io::Error> for NowAuthSrdError {
    fn from(error: std::io::Error) -> NowAuthSrdError {
        NowAuthSrdError::Io(error)
    }
}
