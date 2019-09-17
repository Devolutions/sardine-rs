use base64;
use hyperx;
use hyperx::header;
use std::fmt;
use std::str;
use hyperx::header::RawLike;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AuthenticateScheme {
    Srd,
}

impl fmt::Display for AuthenticateScheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &AuthenticateScheme::Srd => write!(f, "{}", "SRD")?,
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct WWWAuthenticate(Vec<(AuthenticateScheme, Option<Vec<u8>>)>);

impl WWWAuthenticate {
    pub fn new() -> WWWAuthenticate {
        WWWAuthenticate(Vec::new())
    }
    pub fn add_scheme(mut self, scheme: AuthenticateScheme, data: Option<Vec<u8>>) -> Self {
        self.0.push((scheme, data));
        self
    }
    pub fn get_msg(&self, index: usize) -> Option<Vec<u8>> {
        match self.0.get(index) {
            None => None,
            Some(s) => match s.1 {
                None => None,
                Some(ref m) => Some(m.clone()),
            },
        }
    }
}

impl header::Header for WWWAuthenticate {
    fn header_name() -> &'static str {
        "WWW-Authenticate"
    }

    fn parse_header<'a, T>(raw: &'a T) -> hyperx::Result<Self> where T: RawLike<'a>, Self: Sized {
        let mut pairs = Vec::with_capacity(raw.len());
        for line in raw.iter() {
            let header = r#try!(str::from_utf8(line));
            let scheme = "SRD";
            if header.starts_with(scheme) {
                if scheme.len() + 1 < line.len() {
                    let bytes = match base64::decode(&header[scheme.len() + 1..]) {
                        Err(_) => return Err(hyperx::Error::Header),
                        Ok(x) => x,
                    };
                    pairs.push((AuthenticateScheme::Srd, Some(bytes)));
                } else {
                    pairs.push((AuthenticateScheme::Srd, None))
                }
            }
        }
        if pairs.is_empty() {
            Err(hyperx::Error::Header)
        } else {
            Ok(WWWAuthenticate(pairs))
        }
    }

    fn fmt_header(&self, f: &mut header::Formatter) -> fmt::Result {
        f.fmt_line(self)
    }
}

impl fmt::Display for WWWAuthenticate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for scheme in self.0.iter() {
            match scheme.1 {
                Some(ref data) => {
                    write!(f, "{} {}", scheme.0, base64::encode(&data))?;
                }
                None => {
                    write!(f, "{}", scheme.0)?;
                }
            }
        }
        Ok(())
    }
}
