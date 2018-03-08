mod now_auth_srd_message;
mod now_auth_srd_negotiate;
mod now_auth_srd_challenge;
mod now_auth_srd_response;
mod now_auth_srd_confirm;

mod now_auth_srd_result;

pub const NOW_AUTH_SRD_NEGOTIATE_ID: u16 = 1;
pub const NOW_AUTH_SRD_CHALLENGE_ID: u16 = 2;
pub const NOW_AUTH_SRD_RESPONSE_ID: u16 = 3;
pub const NOW_AUTH_SRD_CONFIRM_ID: u16 = 4;
pub const NOW_AUTH_SRD_DELEGATE_ID: u16 = 5;
pub const NOW_AUTH_SRD_RESULT_ID: u16 = 6;

pub use message_types::now_auth_srd_message::NowAuthSrdMessage;
pub use message_types::now_auth_srd_negotiate::NowAuthSrdNegotiate;
pub use message_types::now_auth_srd_challenge::NowAuthSrdChallenge;
pub use message_types::now_auth_srd_response::NowAuthSrdResponse;
pub use message_types::now_auth_srd_confirm::NowAuthSrdConfirm;

pub use message_types::now_auth_srd_result::NowAuthSrdResult;