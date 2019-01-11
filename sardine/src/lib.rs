#![cfg_attr(feature = "wasm", feature(use_extern_macros))]
extern crate byteorder;
extern crate hmac;
extern crate num_bigint;
extern crate rand;
extern crate sha2;

#[cfg(feature = "aes")]
extern crate aes_frast;

extern crate chacha;

#[macro_use]
extern crate cfg_if;

mod cipher;

pub mod blobs;
mod dh_params;
mod messages;
pub mod srd;
mod srd_errors;

pub type Result<T> = std::result::Result<T, srd_errors::SrdError>;
pub use cipher::Cipher;
pub use srd::Srd;
pub use srd_errors::SrdError;

cfg_if! {
    if #[cfg(feature = "wasm")] {
        #[macro_use]
        extern crate wasm_bindgen;
        pub use srd::SrdJsResult;
    }
    else {
        pub mod ffi;
    }
}

#[cfg(test)]
mod tests;

#[cfg(feature = "wasm")]
fn main() {}

//TODO Verify packet size before reading to send error instead of panicking
//TODO Markdown documentation
//TODO Reorder imports
//TODO Reorder traits method
//TODO Verify bignum/Diffie-Hellman optimization
//TODO Comment subsections inside methods
//TODO Create basic blobs described in specs
//TODO Fix webassembly. It will use WebCryptoAPI's javascript function using wasm-bindgen. Still not sure how to use the object oriented model.

// Note: Implementation runs way faster in release mode.
