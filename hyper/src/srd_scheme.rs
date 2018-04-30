use std::fmt;
use hyper;
use hyper::header::Scheme;
use base64::{decode, encode};
use std::str::FromStr;

#[derive(Clone, PartialEq, Debug)]
pub struct SrdAuthorizationScheme {
    pub msg: Vec<u8>,
}

impl Scheme for SrdAuthorizationScheme {
    fn scheme() -> Option<&'static str> {
        Some("SRD")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&encode(&self.msg))
    }
}

impl FromStr for SrdAuthorizationScheme {
    type Err = hyper::Error;

    fn from_str(s: &str) -> Result<SrdAuthorizationScheme, Self::Err> {
        match decode(s) {
            Ok(msg) => Ok(SrdAuthorizationScheme { msg }),
            Err(e) => {
                error!("SrdAuthorizationScheme::from_str base64 error: {}", e);
                Err(hyper::Error::Header)
            }
        }
    }
}
