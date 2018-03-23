use std;
use std::fmt;

#[derive(Debug)]
pub enum NowAuthSrdError {
    Io(std::io::Error),
    BadSequence,
    InvalidKeySize,
    InvalidMac,
}

impl fmt::Display for NowAuthSrdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &NowAuthSrdError::Io(ref error) => error.fmt(f),
            &NowAuthSrdError::BadSequence => write!(f, "Sequence error"),
            &NowAuthSrdError::InvalidKeySize => write!(f, "Key Size error"),
            &NowAuthSrdError::InvalidMac => write!(f, "MAC error"),
        }
    }
}

impl std::error::Error for NowAuthSrdError {
    fn description(&self) -> &str {
        match *self {
            NowAuthSrdError::Io(ref error) => error.description(),
            NowAuthSrdError::BadSequence => "Unexpected packet received!",
            NowAuthSrdError::InvalidKeySize => "Key size must be 256, 512 or 1024",
            NowAuthSrdError::InvalidMac => "MAC is invalid",
        }
    }
}

impl From<std::io::Error> for NowAuthSrdError {
    fn from(error: std::io::Error) -> NowAuthSrdError {
        NowAuthSrdError::Io(error)
    }
}
