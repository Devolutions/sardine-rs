use message_types::NowAuthSrdMessage;

pub struct NowAuthSrdChallenge<'a> {
    packet_type: u16,
    flags: u16,
    key_size: u16,
    generator: [u8; 2],
    prime: &'a [u8],
    public_key: &'a [u8],
    nonce: [u8; 4],
}
