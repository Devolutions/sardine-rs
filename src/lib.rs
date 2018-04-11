extern crate byteorder;
extern crate digest;
extern crate hmac;
extern crate num_bigint;
extern crate rand;
extern crate sha2;

#[cfg(all(target_arch = "wasm32"))]
extern crate crypto;

#[cfg(not(target_arch = "wasm32"))]
extern crate aes_soft;

mod message_types;
mod srd;
mod srd_errors;
mod dh_params;

pub type Result<T> = std::result::Result<T, srd_errors::SrdError>;
pub use srd::Srd;

#[cfg(test)]
mod tests;
