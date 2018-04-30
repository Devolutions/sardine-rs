extern crate base64;
#[macro_use]
extern crate hyper;
#[macro_use]
extern crate log;
extern crate uuid;
use uuid::Uuid;

mod srd_scheme;
mod www_authenticate;

pub use www_authenticate::WWWAuthenticate;
pub use www_authenticate::AuthenticateScheme;
pub use srd_scheme::SrdAuthorizationScheme;

header! { (AuthId, "Auth-ID") => [Uuid] }
