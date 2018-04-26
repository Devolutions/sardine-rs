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

pub mod srd_blob;
mod message_types;
mod srd;
mod srd_errors;
mod dh_params;
pub mod ffi;

pub type Result<T> = std::result::Result<T, srd_errors::SrdError>;
pub use srd::Srd;
pub use srd_errors::SrdError;

#[cfg(test)]
mod tests;

//TODO Verify packet size before reading to send error instead of panicking
//TODO Markdown documentation
//TODO Reorder imports
//TODO Reorder traits method
//TODO Verify bignum/Diffie-Hellman optimization
//TODO Comment subsections inside methods
//TODO Create basic blobs described in specs
//TODO Fix webassembly. It will use WebCryptoAPI's javascript function using wasm-bindgen. Still not sure how to use the object oriented model.

// Note: Implementation runs way faster in release mode.

