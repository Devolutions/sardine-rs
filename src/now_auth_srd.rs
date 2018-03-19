use std;
use std::ffi::CStr;
use Result;
use now_auth_srd_errors::NowAuthSrdError;
use message_types::{NowAuthSrdChallenge, NowAuthSrdConfirm, NowAuthSrdDelegate, NowAuthSrdMessage,
                    NowAuthSrdNegotiate, NowAuthSrdResponse, NowAuthSrdResult};
use message_types::{NOW_AUTH_SRD_CHALLENGE_ID, NOW_AUTH_SRD_CONFIRM_ID, NOW_AUTH_SRD_DELEGATE_ID,
                    NOW_AUTH_SRD_NEGOTIATE_ID, NOW_AUTH_SRD_RESPONSE_ID, NOW_AUTH_SRD_RESULT_ID};

pub struct NowSrd {
    is_server: bool,
    //NowSrdCallbacks cbs;
    keys: [Vec<u8>; 2],
    key_size: u32,
    seq_num: u16,
    username: String,
    password: String,

    cert_data: Vec<u8>,
    cbt_level: u32,

    //buffers: [&'a [u8]; 6],
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

impl NowSrd {
    pub fn new(is_server: bool) -> NowSrd {
        NowSrd {
            is_server,
            keys: [Vec::new(), Vec::new()],
            key_size: 256,
            seq_num: 1,
            username: "".to_string(),
            password: "".to_string(),

            cert_data: Vec::new(),
            cbt_level: 0,

            //buffers: [&[0; 32], &[0; 32], &[0; 32], &[0; 32], &[0; 32], &[0; 32]],
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

    pub fn get_username(&self) -> String {
        self.username.clone()
    }

    pub fn get_password(&self) -> String {
        self.password.clone()
    }

    pub fn set_cert_data(&mut self, buffer: Vec<u8>) -> Result<()> {
        self.cert_data = buffer;
        Ok(())
    }

    pub fn set_credentials(&mut self, username: String, password: String) -> Result<()> {
        self.username = username;
        self.password = password;
        Ok(())
    }

    pub fn set_key_size(&mut self, key_size: u32) -> Result<()> {
        match key_size {
            256 | 512 | 1024 => {
                self.key_size = key_size;
                Ok(())
            }
            _ => Err(NowAuthSrdError::InvalidKeySize),
        }
    }

    pub fn write_msg(&mut self, msg: &NowAuthSrdMessage, buffer: &mut Vec<u8>) -> Result<()> {
        if msg.get_id() == self.seq_num {
            msg.write_to(buffer)?;
            self.seq_num += 1;
            Ok(())
        } else {
            Err(NowAuthSrdError::BadSequence)
        }
    }

    pub fn read_msg<T: NowAuthSrdMessage>(&mut self, buffer: Vec<u8>) -> Result<T>
    where
        T: NowAuthSrdMessage,
    {
        let mut reader = std::io::Cursor::new(buffer);
        let packet = T::read_from(&mut reader)?;
        if packet.get_id() == self.seq_num {
            self.seq_num += 1;
            Ok(packet)
        } else {
            Err(NowAuthSrdError::BadSequence)
        }
    }

    pub fn authenticate(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<bool> {
        if self.is_server {
            match self.seq_num {
                NOW_AUTH_SRD_NEGOTIATE_ID => self.server_negotiate(input_data, output_data)?,
                NOW_AUTH_SRD_CHALLENGE_ID => self.server_challenge(input_data, output_data)?,
                NOW_AUTH_SRD_RESPONSE_ID => self.server_response(input_data, output_data)?,
                NOW_AUTH_SRD_CONFIRM_ID => self.server_confirm(input_data, output_data)?,
                NOW_AUTH_SRD_DELEGATE_ID => self.server_delegate(input_data, output_data)?,
                NOW_AUTH_SRD_RESULT_ID => {
                    self.server_result(input_data, output_data)?;
                    return Ok(true);
                }
                _ => return Err(NowAuthSrdError::BadSequence),
            }
        } else {
            match self.seq_num {
                NOW_AUTH_SRD_NEGOTIATE_ID => self.client_negotiate(input_data, output_data)?,
                NOW_AUTH_SRD_CHALLENGE_ID => self.client_challenge(input_data, output_data)?,
                NOW_AUTH_SRD_RESPONSE_ID => self.client_response(input_data, output_data)?,
                NOW_AUTH_SRD_CONFIRM_ID => self.client_confirm(input_data, output_data)?,
                NOW_AUTH_SRD_DELEGATE_ID => self.client_delegate(input_data, output_data)?,
                NOW_AUTH_SRD_RESULT_ID => {
                    self.client_result(input_data, output_data)?;
                    return Ok(true);
                }
                _ => return Err(NowAuthSrdError::BadSequence),
            }
        }
        self.seq_num += 1;
        Ok(false)
    }

    fn server_negotiate(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn client_negotiate(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn server_challenge(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn client_challenge(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn server_response(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn client_response(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn server_confirm(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn client_confirm(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn server_delegate(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn client_delegate(
        &mut self,
        input_data: &mut Vec<u8>,
        output_data: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    fn server_result(&mut self, input_data: &mut Vec<u8>, output_data: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn client_result(&mut self, input_data: &mut Vec<u8>, output_data: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }
}
