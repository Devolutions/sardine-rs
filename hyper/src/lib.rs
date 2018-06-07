extern crate base64;
#[macro_use]
extern crate hyperx;
#[macro_use]
extern crate log;
extern crate uuid;
use uuid::Uuid;

mod srd_scheme;
mod www_authenticate;

pub use srd_scheme::SrdAuthorizationScheme;
pub use www_authenticate::AuthenticateScheme;
pub use www_authenticate::WWWAuthenticate;

header! { (AuthId, "Auth-ID") => [Uuid] }
