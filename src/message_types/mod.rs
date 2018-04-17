mod srd_message;
mod srd_mac;
mod srd_initiate;
mod srd_offer;
mod srd_accept;
mod srd_confirm;
mod srd_delegate;
mod srd_blob;

pub const SRD_SIGNATURE: u32 = 00445253;

pub mod srd_msg_id {
    pub const SRD_INITIATE_MSG_ID: u8 = 1;
    pub const SRD_OFFER_MSG_ID: u8 = 2;
    pub const SRD_ACCEPT_MSG_ID: u8 = 3;
    pub const SRD_CONFIRM_MSG_ID: u8 = 4;
    pub const SRD_DELEGATE_MSG_ID: u8 = 5;
}

pub mod srd_flags {
    pub const SRD_FLAG_MAC: u16 = 0x0001;
    pub const SRD_FLAG_CBT: u16 = 0x0002;
}

pub use message_types::srd_mac::SrdMac;
pub use message_types::srd_message::SrdMessage;
pub use message_types::srd_initiate::SrdInitiate;
pub use message_types::srd_offer::SrdOffer;
pub use message_types::srd_accept::SrdAccept;
pub use message_types::srd_confirm::SrdConfirm;
pub use message_types::srd_delegate::SrdDelegate;
pub use message_types::srd_blob::SrdBlob;
pub use message_types::srd_blob::SrdBlobInterface;

fn expand_start<T: Default>(buffer: &mut Vec<T>, new_size: usize) {
    if new_size > buffer.len() {
        for _ in 0..(new_size - buffer.len()) {
            buffer.insert(0, Default::default());
        }
    }
}
