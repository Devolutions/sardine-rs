use std;
use std::ffi::CStr;

use rand;
use rand::{OsRng, Rng};

use num::bigint::{BigUint, RandBigInt};

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use Result;
use now_auth_srd_errors::NowAuthSrdError;
use message_types::*;
use message_types::now_auth_srd_id::*;
use dh_params::{SrdDhParams, SRD_DH_PARAMS};

pub struct NowSrd {
    is_server: bool,
    //NowSrdCallbacks cbs;
    keys: [Vec<u8>; 2],
    key_size: u16,
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
    private_key: Vec<u8>,
    secret_key: Vec<u8>,

    rng: OsRng,
}

impl NowSrd {
    pub fn new(is_server: bool) -> Result<NowSrd> {
        Ok(NowSrd {
            is_server,
            keys: [Vec::new(), Vec::new()],
            key_size: 256,
            seq_num: 0,
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
            private_key: Vec::new(),
            secret_key: Vec::new(),

            rng: OsRng::new()?,
        })
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

    pub fn set_key_size(&mut self, key_size: u16) -> Result<()> {
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

    pub fn read_msg<T: NowAuthSrdMessage>(&mut self, buffer: &mut Vec<u8>) -> Result<T>
    where
        T: NowAuthSrdMessage,
    {
        let mut reader = std::io::Cursor::new(buffer.clone());
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
                0 => self.server_0(input_data, output_data)?,
                1 => self.server_1(input_data, output_data)?,
                2 => self.server_2(input_data, output_data)?,
                3 => {
                    self.server_3(input_data, output_data)?;
                    return Ok(true);
                }
                _ => return Err(NowAuthSrdError::BadSequence),
            }
        } else {
            match self.seq_num {
                0 => self.client_0(input_data, output_data)?,
                1 => self.client_1(input_data, output_data)?,
                2 => self.client_2(input_data, output_data)?,
                3 => self.client_3(input_data, output_data)?,
                4 => {
                    self.client_4(input_data, output_data)?;
                    return Ok(true);
                }
                _ => return Err(NowAuthSrdError::BadSequence),
            }
        }
        self.seq_num += 1;
        Ok(false)
    }

    fn client_0(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        let msg = NowAuthSrdNegotiate::new(self.key_size);
        self.write_msg(&msg, &mut output_data)?;
        Ok(())
    }

    fn server_0(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        let in_packet = self.read_msg::<NowAuthSrdNegotiate>(input_data)?;
        self.set_key_size(in_packet.key_size)?;
        self.find_dh_parameters()?;

        let g = BigUint::from_bytes_be(&self.generator);
        let p = BigUint::from_bytes_be(&self.prime);
        let private_key = self.rng.gen_biguint((self.key_size as usize) * 8);
        let public_key = g.modpow(&private_key, &p);

        self.private_key = private_key.to_bytes_be();

        let mut nonce = [0u8; 32];
        self.rng.fill_bytes(&mut nonce);

        self.server_nonce = nonce;

        let out_packet = NowAuthSrdChallenge::new(
            in_packet.key_size,
            self.generator,
            self.prime.clone(),
            public_key.to_bytes_be(),
            nonce,
        );
        self.write_msg(&out_packet, &mut output_data);
        Ok(())
    }

    fn client_1(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        let in_packet = self.read_msg::<NowAuthSrdChallenge>(input_data)?;

        let g = BigUint::from_bytes_be(&in_packet.generator);
        let p = BigUint::from_bytes_be(&in_packet.prime);
        let private_key = self.rng.gen_biguint((self.key_size as usize) * 8);
        let public_key = g.modpow(&private_key, &p);

        let mut nonce = [0u8; 32];
        self.rng.fill_bytes(&mut nonce);

        self.client_nonce = nonce;
        self.server_nonce = in_packet.nonce;
        self.secret_key = BigUint::from_bytes_be(&in_packet.public_key)
            .modpow(&private_key, &p)
            .to_bytes_be();

        self.derive_keys();

        //TODO: cbt and mac

        /*let out_packet = NowAuthSrdResponse::new(
            in_packet.key_size,
            public_key.to_bytes_be(),
            nonce,
            cbt,
            mac,
        );*/

        Ok(())
    }

    fn server_1(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn client_2(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn server_2(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn client_3(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn server_3(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn client_4(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn find_dh_parameters(&mut self) -> Result<()> {
        match self.key_size {
            256 => {
                self.generator = SRD_DH_PARAMS[0].g_data.clone();
                self.prime = SRD_DH_PARAMS[0].p_data.to_vec();
                Ok(())
            }
            512 => {
                self.generator = SRD_DH_PARAMS[1].g_data.clone();
                self.prime = SRD_DH_PARAMS[1].p_data.to_vec();
                Ok(())
            }
            1024 => {
                self.generator = SRD_DH_PARAMS[2].g_data.clone();
                self.prime = SRD_DH_PARAMS[2].p_data.to_vec();
                Ok(())
            }
            _ => Err(NowAuthSrdError::InvalidKeySize),
        }
    }

    fn derive_keys(&mut self) {
        let mut hash = Sha256::new();
        hash.input(&self.client_nonce);
        hash.input(&self.secret_key);
        hash.input(&self.server_nonce);

        hash.result(&mut self.delegation_key);

        hash = Sha256::new();
        hash.input(&self.client_nonce);
        hash.input(&self.secret_key);
        hash.input(&self.server_nonce);

        hash.result(&mut self.integrity_key);

        hash = Sha256::new();
        hash.input(&self.client_nonce);
        hash.input(&self.server_nonce);

        hash.result(&mut self.iv);
    }
}
