use std;
use Result;
use now_auth_srd_errors::NowAuthSrdError;
use message_types::{NowAuthSrdMessage, NowAuthSrdNegotiate, NowAuthSrdChallenge, NowAuthSrdResponse,
                    NowAuthSrdConfirm, NowAuthSrdDelegate, NowAuthSrdResult};
use message_types::{NOW_AUTH_SRD_CHALLENGE_ID, NOW_AUTH_SRD_CONFIRM_ID, NOW_AUTH_SRD_DELEGATE_ID,
                    NOW_AUTH_SRD_NEGOTIATE_ID, NOW_AUTH_SRD_RESPONSE_ID, NOW_AUTH_SRD_RESULT_ID};

pub struct NowSrd<'a> {
    is_server: bool,
    //NowSrdCallbacks cbs;
    keys: &'a [u8],
    key_size: u16,
    seq_num: u16,
    username: &'a str,
    password: &'a str,

    cert_data: &'a [u8],
    cert_size: usize,
    cbt_level: u32,

    buffers: [&'a [u8]; 6],

    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    delegation_key: [u8; 32],
    integrity_key: [u8; 32],
    iv: [u8; 32],

    generator: [u8; 2],

    prime: Vec<u8>,
    peer_key: Vec<u8>,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl<'a> NowSrd<'a> {
    pub fn new(is_server: bool) -> NowSrd<'a> {
        NowSrd {
            is_server,
            keys: &[0; 32],
            key_size: 0,
            seq_num: 1,
            username: "hello",
            password: "world!",

            cert_data: &[0; 32],
            cert_size: 0,
            cbt_level: 0,

            buffers: [&[0; 32], &[0; 32], &[0; 32], &[0; 32], &[0; 32], &[0; 32]],

            client_nonce: [0; 32],
            server_nonce: [0; 32],
            delegation_key: [0; 32],
            integrity_key: [0; 32],
            iv: [0; 32],

            generator: [0; 2],

            prime: Vec::new(),
            peer_key: Vec::new(),
            public_key: Vec::new(),
            private_key: Vec::new(),
            secret_key: Vec::new(),
        }
    }

    pub fn now_srd_write_msg(&mut self, msg: &NowAuthSrdMessage, buffer: &mut Vec<u8>) -> Result<()> {
        if msg.get_id() == self.seq_num {
            msg.write_to(buffer)?;
            self.seq_num += 1;
            Ok(())
        } else {
            Err(NowAuthSrdError::BadSequence)
        }
    }

    pub fn now_srd_read_msg<T: NowAuthSrdMessage>(&mut self, buffer: Vec<u8>) -> Result<T>
    where
        T: NowAuthSrdMessage,
    {
        let mut reader = std::io::Cursor::new(buffer);
        let packet = T::read_from(&mut reader)?;
        if packet.get_id() == self.seq_num {
            self.seq_num += 1;
            Ok(packet)
        }
        else {
            Err(NowAuthSrdError::BadSequence)
        }
    }
}
