mod srd_message;
mod srd_negotiate;
mod srd_challenge;
mod srd_response;
mod srd_confirm;
mod srd_delegate;
mod srd_result;
mod srd_logon_blob;

pub mod srd_id {
    pub const SRD_NEGOTIATE_ID: u16 = 1;
    pub const SRD_CHALLENGE_ID: u16 = 2;
    pub const SRD_RESPONSE_ID: u16 = 3;
    pub const SRD_CONFIRM_ID: u16 = 4;
    pub const SRD_DELEGATE_ID: u16 = 5;
    pub const SRD_RESULT_ID: u16 = 6;
    pub const SRD_LOGON_BLOB_ID: u16 = 1;
}

pub use message_types::srd_message::SrdMessage;
pub use message_types::srd_negotiate::SrdNegotiate;
pub use message_types::srd_challenge::SrdChallenge;
pub use message_types::srd_response::SrdResponse;
pub use message_types::srd_confirm::SrdConfirm;
pub use message_types::srd_delegate::SrdDelegate;
pub use message_types::srd_result::SrdResult;
pub use message_types::srd_logon_blob::SrdLogonBlob;

fn expand_start<T: Default>(buffer: &mut Vec<T>, new_size: usize) {
    if new_size > buffer.len() {
        for _ in 0..(new_size - buffer.len()) {
            buffer.insert(0, Default::default());
        }
    }
}
