use std;
use std::fmt;

#[derive(Debug)]
pub enum NowAuthSrdError {
    Io(std::io::Error),
    BadSequence(String),
}

impl fmt::Display for NowAuthSrdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &NowAuthSrdError::Io(ref error) => error.fmt(f),
            &NowAuthSrdError::BadSequence(ref desc) => write!(f, "Sequence error: {}", desc),
        }
    }
}

impl std::error::Error for NowAuthSrdError {
    fn description(&self) -> &str {
        match *self {
            NowAuthSrdError::Io(ref error) => error.description(),
            NowAuthSrdError::BadSequence(_) => "Unexpected packet received!",
        }
    }
}

impl From<std::io::Error> for NowAuthSrdError {
    fn from(error: std::io::Error) -> NowAuthSrdError {
        NowAuthSrdError::Io(error)
    }
}