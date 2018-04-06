use std;
use std::io::{Read, Write};

use rand::{OsRng, Rng};

use num_bigint::BigUint;

use digest::Digest;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use Result;
use now_auth_srd_errors::NowAuthSrdError;
use message_types::*;
use dh_params::SRD_DH_PARAMS;

pub struct NowSrd {
    credentials_callback: Option<fn(&String, &String) -> bool>,

    is_server: bool,
    key_size: u16,
    seq_num: u16,
    username: String,
    password: String,

    cert_data: Option<Vec<u8>>,

    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    delegation_key: [u8; 32],
    integrity_key: [u8; 32],
    iv: [u8; 32],

    generator: BigUint,

    prime: BigUint,
    private_key: BigUint,
    secret_key: Vec<u8>,

    rng: OsRng,
}

impl NowSrd {
    pub fn new(is_server: bool) -> Result<NowSrd> {
        Ok(NowSrd {
            credentials_callback: None,

            is_server,
            key_size: 256,
            seq_num: 0,
            username: "".to_string(),
            password: "".to_string(),

            cert_data: None,

            client_nonce: [0; 32],
            server_nonce: [0; 32],
            delegation_key: [0; 32],
            integrity_key: [0; 32],
            iv: [0; 32],

            generator: BigUint::from_bytes_be(&[0]),

            prime: BigUint::from_bytes_be(&[0]),
            private_key: BigUint::from_bytes_be(&[0]),
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

    pub fn set_credentials_callback(&mut self, callback: fn(&String, &String) -> bool) {
        self.credentials_callback = Some(callback)
    }

    pub fn set_cert_data(&mut self, buffer: Vec<u8>) -> Result<()> {
        self.cert_data = Some(buffer);
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
        let seq_num = if self.is_server {
            (msg.get_id() - 1) / 2
        } else {
            msg.get_id() / 2
        };

        if seq_num == self.seq_num {
            msg.write_to(buffer)?;
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

        let seq_num = if self.is_server {
            (packet.get_id() - 1) / 2
        } else {
            packet.get_id() / 2
        };

        if seq_num == self.seq_num {
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
                2 => {
                    self.server_2(input_data, output_data)?;
                    self.seq_num += 1;
                    return Ok(true);
                }
                3 => return Ok(true),
                _ => return Err(NowAuthSrdError::BadSequence),
            }
        } else {
            match self.seq_num {
                0 => self.client_0(output_data)?,
                1 => self.client_1(input_data, output_data)?,
                2 => self.client_2(input_data, output_data)?,
                3 => {
                    self.client_3(input_data)?;
                    return Ok(true);
                }
                _ => return Err(NowAuthSrdError::BadSequence),
            }
        }
        self.seq_num += 1;
        Ok(false)
    }

    // Client negotiate
    fn client_0(&mut self, mut output_data: &mut Vec<u8>) -> Result<()> {
        // Negotiate
        let msg = NowAuthSrdNegotiate::new(self.key_size);
        self.write_msg(&msg, &mut output_data)?;
        Ok(())
    }

    // Server negotiate -> challenge
    fn server_0(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        // Negotiate
        let in_packet = self.read_msg::<NowAuthSrdNegotiate>(input_data)?;
        self.set_key_size(in_packet.key_size)?;
        self.find_dh_parameters()?;

        // Challenge
        let mut private_key_bytes = vec![0u8; self.key_size as usize];
        self.rng.fill_bytes(&mut private_key_bytes);
        self.private_key = BigUint::from_bytes_be(&private_key_bytes);

        let public_key = self.generator.modpow(&self.private_key, &self.prime);

        self.rng.fill_bytes(&mut self.server_nonce);

        let out_packet = NowAuthSrdChallenge::new(
            in_packet.key_size,
            self.generator.to_bytes_be(),
            self.prime.to_bytes_be(),
            public_key.to_bytes_be(),
            self.server_nonce,
        );
        self.write_msg(&out_packet, &mut output_data)?;
        Ok(())
    }

    // Client challenge -> reponse
    fn client_1(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        //Challenge
        let in_packet = self.read_msg::<NowAuthSrdChallenge>(input_data)?;

        self.generator = BigUint::from_bytes_be(&in_packet.generator);
        self.prime = BigUint::from_bytes_be(&in_packet.prime);

        let mut private_key_bytes = vec![0u8; self.key_size as usize];
        self.rng.fill_bytes(&mut private_key_bytes);
        self.private_key = BigUint::from_bytes_be(&private_key_bytes);

        let public_key = self.generator.modpow(&self.private_key, &self.prime);

        self.rng.fill_bytes(&mut self.client_nonce);

        self.server_nonce = in_packet.nonce;
        self.secret_key = BigUint::from_bytes_be(&in_packet.public_key)
            .modpow(&self.private_key, &self.prime)
            .to_bytes_be();

        self.derive_keys()?;

        // Generate cbt
        let cbt;

        match self.cert_data {
            None => cbt = None,
            Some(ref cert) => {
                let mut hmac = Hmac::<Sha256>::new_varkey(&self.integrity_key)?;

                hmac.input(&self.client_nonce);
                hmac.input(&cert);

                let mut cbt_data: [u8; 32] = [0u8; 32];
                hmac.result().code().to_vec().write_all(&mut cbt_data)?;
                cbt = Some(cbt_data);
            }
        }

        let out_packet = NowAuthSrdResponse::new(
            in_packet.key_size,
            public_key.to_bytes_be(),
            self.client_nonce,
            cbt,
            &self.integrity_key,
        )?;

        self.write_msg(&out_packet, &mut output_data)?;
        Ok(())
    }

    // Server response -> confirm
    fn server_1(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        // Response
        let in_packet = self.read_msg::<NowAuthSrdResponse>(input_data)?;
        self.client_nonce = in_packet.nonce;

        self.secret_key = BigUint::from_bytes_be(&in_packet.public_key)
            .modpow(&self.private_key, &self.prime)
            .to_bytes_be();

        self.derive_keys()?;

        in_packet.verify_mac(&self.integrity_key)?;

        // Verify client cbt
        match self.cert_data {
            None => {
                if in_packet.has_cbt() {
                    return Err(NowAuthSrdError::InvalidCert);
                }
            }
            Some(ref c) => {
                if !in_packet.has_cbt() {
                    return Err(NowAuthSrdError::InvalidCert);
                }
                let mut hmac = Hmac::<Sha256>::new_varkey(&self.integrity_key)?;

                hmac.input(&self.client_nonce);
                hmac.input(&c);

                let mut cbt_data: [u8; 32] = [0u8; 32];
                hmac.result().code().to_vec().write_all(&mut cbt_data)?;
                if cbt_data != in_packet.cbt {
                    return Err(NowAuthSrdError::InvalidCbt);
                }
            }
        }

        // Confirm
        // Generate server cbt
        let cbt;
        match self.cert_data {
            None => cbt = None,
            Some(ref cert) => {
                let mut hmac = Hmac::<Sha256>::new_varkey(&self.integrity_key)?;

                hmac.input(&self.server_nonce);
                hmac.input(&cert);

                let mut cbt_data: [u8; 32] = [0u8; 32];
                hmac.result().code().to_vec().write_all(&mut cbt_data)?;
                cbt = Some(cbt_data);
            }
        }

        let out_packet = NowAuthSrdConfirm::new(cbt, &self.integrity_key)?;
        self.write_msg(&out_packet, &mut output_data)?;
        Ok(())
    }

    // Client confirm -> delegate
    fn client_2(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        // Confirm
        let in_packet = self.read_msg::<NowAuthSrdConfirm>(input_data)?;

        in_packet.verify_mac(&self.integrity_key)?;

        // Verify Server cbt
        match self.cert_data {
            None => {
                if in_packet.has_cbt() {
                    return Err(NowAuthSrdError::InvalidCert);
                }
            }
            Some(ref c) => {
                if !in_packet.has_cbt() {
                    return Err(NowAuthSrdError::InvalidCert);
                }
                let mut hmac = Hmac::<Sha256>::new_varkey(&self.integrity_key)?;

                hmac.input(&self.server_nonce);
                hmac.input(&c);

                let mut cbt_data: [u8; 32] = [0u8; 32];
                hmac.result().code().to_vec().write_all(&mut cbt_data)?;
                if cbt_data != in_packet.cbt {
                    return Err(NowAuthSrdError::InvalidCbt);
                }
            }
        }

        // Delegate
        let logon_blob = NowAuthSrdLogonBlob::new(
            &convert_and_pad_to_cstr(&mut self.rng, &self.username)?,
            &convert_and_pad_to_cstr(&mut self.rng, &self.password)?,
            &self.iv[0..16],
            &self.delegation_key,
        )?;

        let message = NowAuthSrdDelegate::new(logon_blob, &self.integrity_key)?;
        self.write_msg(&message, &mut output_data)?;
        Ok(())
    }

    // Server delegate -> result
    fn server_2(&mut self, input_data: &mut Vec<u8>, mut output_data: &mut Vec<u8>) -> Result<()> {
        // Receive delegate and verify credentials...
        let in_packet = self.read_msg::<NowAuthSrdDelegate>(input_data)?;
        in_packet.verify_mac(&self.integrity_key)?;

        let credentials_data = in_packet.get_data(&self.iv[0..16], &self.delegation_key)?;

        self.username = convert_and_unpad_from_cstr(&credentials_data[0..128])?;
        self.password = convert_and_unpad_from_cstr(&credentials_data[128..256])?;

        match self.credentials_callback {
            Some(c) => {
                if c(&self.username, &self.password) {
                    let message = NowAuthSrdResult::new(0, &self.integrity_key)?;
                    self.write_msg(&message, &mut output_data)?;
                    Ok(())
                } else {
                    let message = NowAuthSrdResult::new(1, &self.integrity_key)?;
                    self.write_msg(&message, &mut output_data)?;
                    Err(NowAuthSrdError::InvalidCredentials)
                }
            }
            None => Err(NowAuthSrdError::MissingCallback),
        }
    }

    // Client result
    fn client_3(&mut self, input_data: &mut Vec<u8>) -> Result<()> {
        let in_packet = self.read_msg::<NowAuthSrdResult>(input_data)?;
        in_packet.verify_mac(&self.integrity_key)?;

        if in_packet.status != 0 {
            Err(NowAuthSrdError::InvalidCredentials)
        } else {
            Ok(())
        }
    }

    fn find_dh_parameters(&mut self) -> Result<()> {
        match self.key_size {
            256 => {
                self.generator = BigUint::from_bytes_be(SRD_DH_PARAMS[0].g_data);
                self.prime = BigUint::from_bytes_be(SRD_DH_PARAMS[0].p_data);
                Ok(())
            }
            512 => {
                self.generator = BigUint::from_bytes_be(SRD_DH_PARAMS[1].g_data);
                self.prime = BigUint::from_bytes_be(SRD_DH_PARAMS[1].p_data);
                Ok(())
            }
            1024 => {
                self.generator = BigUint::from_bytes_be(SRD_DH_PARAMS[2].g_data);
                self.prime = BigUint::from_bytes_be(SRD_DH_PARAMS[2].p_data);
                Ok(())
            }
            _ => Err(NowAuthSrdError::InvalidKeySize),
        }
    }

    fn derive_keys(&mut self) -> Result<()> {
        let mut hash = Sha256::new();
        hash.input(&self.client_nonce);
        hash.input(&self.secret_key);
        hash.input(&self.server_nonce);

        hash.result().to_vec().write_all(&mut self.delegation_key)?;

        hash = Sha256::new();
        hash.input(&self.server_nonce);
        hash.input(&self.secret_key);
        hash.input(&self.client_nonce);

        hash.result().to_vec().write_all(&mut self.integrity_key)?;

        hash = Sha256::new();
        hash.input(&self.client_nonce);
        hash.input(&self.server_nonce);

        hash.result().to_vec().write_all(&mut self.iv)?;
        Ok(())
    }
}

fn convert_and_pad_to_cstr(rng: &mut OsRng, str: &str) -> Result<[u8; 128]> {
    //TODO: Block large username and password
    let mut cstr = [0u8; 128];
    std::ffi::CString::new(str)?
        .as_bytes_with_nul()
        .read(&mut cstr)?;
    let index = match cstr.iter().enumerate().find(|&x| *x.1 == b'\x00') {
        None => {
            return Err(NowAuthSrdError::InvalidCstr);
        }
        Some(t) => t.0,
    };
    for i in index + 1..cstr.len() {
        cstr[i] = rng.gen::<u8>();
    }
    Ok(cstr)
}

fn convert_and_unpad_from_cstr(data: &[u8]) -> Result<String> {
    let index = match data.iter().enumerate().find(|&x| *x.1 == b'\x00') {
        None => {
            return Err(NowAuthSrdError::InvalidCstr);
        }
        Some(t) => t.0,
    };
    Ok(String::from_utf8(data[0..index].to_vec())?)
}
