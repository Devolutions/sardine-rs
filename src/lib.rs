extern crate byteorder;
extern crate num_bigint;
extern crate rand;

#[cfg(not(target_arch = "wasm32"))]
extern crate crypto;

#[cfg(all(target_arch = "wasm32"))]
extern crate aes_soft;

mod message_types;
mod now_auth_srd;
mod now_auth_srd_errors;
mod dh_params;

pub type Result<T> = std::result::Result<T, now_auth_srd_errors::NowAuthSrdError>;
pub use now_auth_srd::NowSrd;

#[cfg(test)]
mod tests;
