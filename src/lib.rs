extern crate byteorder;
extern crate crypto;
extern crate num;
extern crate rand;

pub type Result<T> = std::result::Result<T, now_auth_srd_errors::NowAuthSrdError>;

mod message_types;
mod now_auth_srd;
mod now_auth_srd_errors;
mod dh_params;

#[cfg(test)]
mod tests;
