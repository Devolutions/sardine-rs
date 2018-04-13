extern crate byteorder;
extern crate digest;
extern crate hmac;
extern crate num_bigint;
extern crate rand;
extern crate sha2;

#[cfg(not(target_arch = "wasm32"))]
extern crate crypto;

#[cfg(all(target_arch = "wasm32"))]
extern crate aes_soft;
#[cfg(all(target_arch = "wasm32"))]
extern crate wasm_bindgen;

mod message_types;
mod srd;
mod srd_errors;
mod dh_params;

pub type Result<T> = std::result::Result<T, srd_errors::SrdError>;
pub use srd::Srd;

#[cfg(test)]
mod tests;
