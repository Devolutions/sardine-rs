use std;
use std::io::Write;

#[cfg(not(feature = "wasm"))]
use rand::{EntropyRng, RngCore};

use num_bigint::BigUint;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use cipher::Cipher;
use Result;

use blobs::{Blob, SrdBlob};
use dh_params::SRD_DH_PARAMS;
use messages::*;
use srd_errors::SrdError;

cfg_if! {
    if #[cfg(feature = "wasm")] {
        use wasm_bindgen::prelude::*;
        #[wasm_bindgen]
        pub struct SrdJsResult {
            output_data: Vec<u8>,
            res_code: i32,
        }

        #[wasm_bindgen]
        impl SrdJsResult {
            pub fn output_data(&self) -> Vec<u8> {
                self.output_data.clone()
            }

            pub fn res_code(&self) -> i32 {
                self.res_code
            }
        }

        // WASM public function
        #[wasm_bindgen]
        impl Srd {
            #[wasm_bindgen(constructor)]
            pub fn new(is_server: bool) -> Srd {
                Srd::_new(is_server)
            }

            pub fn authenticate(&mut self, input_data: &[u8]) -> SrdJsResult {
                let mut output_data = Vec::new();
                self._authenticate(&input_data, &mut output_data).unwrap();
                SrdJsResult {
                    output_data,
                    res_code: -1,
                }
                /*match self._authenticate(&input_data, &mut output_data) {
                    Err(_) => SrdJsResult {
                        output_data,
                        res_code: -1,
                    },
                    Ok(b) => {
                        if b {
                            SrdJsResult {
                                output_data,
                                res_code: 0,
                            }
                        } else {
                            SrdJsResult {
                                output_data,
                                res_code: 1,
                            }
                        }
                    }
                }*/
            }

            pub fn get_delegation_key(&self) -> Vec<u8> {
                self.delegation_key.to_vec()
            }

            pub fn get_integrity_key(&self) -> Vec<u8> {
                self.integrity_key.to_vec()
            }

            pub fn set_cert_data(&mut self, buffer: Vec<u8>) {
                self._set_cert_data(buffer).unwrap();
            }
        }
    }
    else {
        // Native public functions
        #[cfg(not(feature = "wasm"))]
        impl Srd {
            pub fn new(is_server: bool) -> Srd {
                Srd::_new(is_server)
            }

            pub fn authenticate(&mut self, input_data: &[u8], output_data: &mut Vec<u8>) -> Result<bool> {
                self._authenticate(&input_data, output_data)
            }

            pub fn get_keys(&self) -> ([u8; 32], [u8; 32]) {
                (self.delegation_key, self.integrity_key)
            }

            pub fn get_delegation_key(&self) -> Vec<u8> {
                self.delegation_key.to_vec()
            }

            pub fn get_integrity_key(&self) -> Vec<u8> {
                self.integrity_key.to_vec()
            }

            pub fn set_cert_data(&mut self, buffer: Vec<u8>) -> Result<()> {
                self._set_cert_data(buffer)?;
                Ok(())
            }

            pub fn get_output_data(&self) -> &Option<Vec<u8>> {
                &self.output_data
            }

            pub fn set_output_data(&mut self, output_data: Vec<u8>) {
                self.output_data = Some(output_data);
            }
        }

    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct Srd {
    blob: Option<SrdBlob>,
    output_data: Option<Vec<u8>>,

    is_server: bool,
    key_size: u16,
    seq_num: u8,
    state: u8,

    messages: Vec<Vec<u8>>,

    cert_data: Option<Vec<u8>>,

    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    delegation_key: [u8; 32],
    integrity_key: [u8; 32],
    iv: [u8; 32],

    supported_ciphers: Vec<Cipher>,
    cipher: Cipher,

    generator: BigUint,

    prime: BigUint,
    private_key: BigUint,
    secret_key: Vec<u8>,
}

// Same implementation, both public
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl Srd {
    pub fn set_raw_blob(&mut self, blob: SrdBlob) {
        self.blob = Some(blob);
    }
}

impl Srd {
    fn _new(is_server: bool) -> Srd {
        let supported_ciphers;
        if cfg!(feature = "fips") {
            supported_ciphers = vec![Cipher::AES256];
        } else if cfg!(feature = "aes") {
            supported_ciphers = vec![Cipher::XChaCha20, Cipher::ChaCha20, Cipher::AES256];
        } else {
            supported_ciphers = vec![Cipher::XChaCha20, Cipher::ChaCha20];
        }

        Srd {
            blob: None,
            output_data: None,

            is_server,
            key_size: 256,
            seq_num: 0,
            state: 0,

            messages: Vec::new(),

            cert_data: None,

            client_nonce: [0; 32],
            server_nonce: [0; 32],
            delegation_key: [0; 32],
            integrity_key: [0; 32],
            iv: [0; 32],

            supported_ciphers,
            cipher: Cipher::XChaCha20,

            generator: BigUint::from_bytes_be(&[0]),

            prime: BigUint::from_bytes_be(&[0]),
            private_key: BigUint::from_bytes_be(&[0]),
            secret_key: Vec::new(),
        }
    }

    fn _authenticate(&mut self, input_data: &[u8], output_data: &mut Vec<u8>) -> Result<bool> {
        // We don't want anybody to access previous output_data.
        self.output_data = None;

        if self.is_server {
            match self.state {
                0 => self.server_authenticate_0(input_data, output_data)?,
                1 => self.server_authenticate_1(input_data, output_data)?,
                2 => {
                    self.server_authenticate_2(input_data)?;
                    self.state += 1;
                    return Ok(true);
                }
                _ => return Err(SrdError::BadSequence),
            }
        } else {
            match self.state {
                0 => self.client_authenticate_0(output_data)?,
                1 => self.client_authenticate_1(input_data, output_data)?,
                2 => {
                    self.client_authenticate_2(input_data, output_data)?;
                    self.state += 1;
                    return Ok(true);
                }
                _ => return Err(SrdError::BadSequence),
            }
        }
        self.state += 1;
        Ok(false)
    }

    fn _set_cert_data(&mut self, buffer: Vec<u8>) -> Result<()> {
        self.cert_data = Some(buffer);
        Ok(())
    }

    pub fn set_ciphers(&mut self, ciphers: Vec<Cipher>) -> Result<()> {
        if cfg!(feature = "fips") {
            return Err(SrdError::Cipher);
        }

        if cfg!(not(feature = "aes")) {
            if ciphers.contains(&Cipher::AES256) {
                return Err(SrdError::Cipher);
            }
        }

        self.supported_ciphers = ciphers;
        Ok(())
    }

    pub fn get_blob<T: Blob>(&self) -> Result<Option<T>> {
        if self.blob.is_some() {
            let blob = self.blob.as_ref().unwrap();
            if blob.blob_type() == T::blob_type() {
                let mut cursor = std::io::Cursor::new(blob.data());
                return Ok(Some(T::read_from(&mut cursor)?));
            }
        }
        Ok(None)
    }

    pub fn set_blob<T: Blob>(&mut self, blob: T) -> Result<()> {
        let mut data = Vec::new();
        blob.write_to(&mut data)?;
        self.blob = Some(SrdBlob::new(T::blob_type(), &data));
        Ok(())
    }

    pub fn get_raw_blob(&self) -> Option<SrdBlob> {
        return self.blob.clone();
    }

    fn set_key_size(&mut self, key_size: u16) -> Result<()> {
        match key_size {
            256 | 512 | 1024 => {
                self.key_size = key_size;
                Ok(())
            }
            _ => Err(SrdError::InvalidKeySize),
        }
    }

    fn read_msg(&mut self, buffer: &[u8]) -> Result<SrdMessage> {
        let mut reader = std::io::Cursor::new(buffer);
        let msg = SrdMessage::read_from(&mut reader)?;

        if msg.seq_num() != self.seq_num {
            return Err(SrdError::BadSequence);
        }
        self.seq_num += 1;

        // Keep the message to calculate future mac value
        self.messages.push(Vec::from(buffer));

        // Verify mac value right now. We can't validate mac value for accept msg since we need information from
        // the message to generate the integrety key. So only for this message type, it is verified later.
        if msg.has_mac() && msg.msg_type() != srd_msg_id::SRD_ACCEPT_MSG_ID {
            self.validate_mac(&msg)?;
        }

        Ok(msg)
    }

    fn write_msg(&mut self, msg: &mut SrdMessage, buffer: &mut Vec<u8>) -> Result<()> {
        if msg.signature() != SRD_SIGNATURE {
            return Err(SrdError::InvalidSignature);
        }

        if msg.seq_num() != self.seq_num {
            return Err(SrdError::BadSequence);
        }

        // Keep the message to calculate future mac value. The message doesn't contain the MAC since it is not calculated yet
        // It is not a problem since the all MAC are not included in MAC calculation
        let mut v_temp = Vec::new();
        msg.write_to(&mut v_temp)?;
        self.messages.push(v_temp);

        if msg.has_mac() {
            msg.set_mac(&self.compute_mac()?)
                .expect("Should never happen, has_mac returned true");
        }

        // Remove the last message to insert it again with the mac value (not really needed, just to keep exactly what it is sent.
        self.messages.pop();
        msg.write_to(buffer)?;
        self.messages.push(buffer.clone());

        self.seq_num += 1;

        Ok(())
    }

    fn compute_mac(&self) -> Result<Vec<u8>> {
        let mut hmac = Hmac::<Sha256>::new_varkey(&self.integrity_key)?;
        hmac.input(&self.get_mac_data()
            .map_err(|_| SrdError::Internal("MAC can't be calculated".to_owned()))?);
        Ok(hmac.result().code().to_vec())
    }

    fn validate_mac(&self, msg: &SrdMessage) -> Result<()> {
        if msg.has_mac() {
            let mut hmac = Hmac::<Sha256>::new_varkey(&self.integrity_key)?;
            hmac.input(&self.get_mac_data()
                .map_err(|_| SrdError::Internal("MAC can't be calculated".to_owned()))?);

            if let Some(mac) = msg.mac() {
                hmac.verify(mac).map_err(|_| SrdError::InvalidMac)
            } else {
                Err(SrdError::Internal(
                    "Msg should have a MAC but we can't get it".to_owned(),
                ))
            }
        } else {
            // No mac in the message => Nothing to verify
            Ok(())
        }
    }

    // Send back all the data that has to be used to calculate the MAC. We used all messages, without all MAC fields
    fn get_mac_data(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        for message in &self.messages {
            let mut clone = message.clone();
            let hdr = SrdHeader::read_from(&mut clone.as_slice())?;
            if hdr.has_mac() {
                // Keep the message without the MAC at the end (32 bytes)
                let slice = message.as_slice();
                let last_index = slice.len() - 32;
                result.write(&slice[0..last_index])?;
            } else {
                result.write(message.as_slice())?;
            }
        }

        Ok(result)
    }

    // Client initiate
    fn client_authenticate_0(&mut self, mut output_data: &mut Vec<u8>) -> Result<()> {
        let mut cipher_flags = 0u32;
        for c in &self.supported_ciphers {
            cipher_flags |= c.flag();
        }

        if cipher_flags == 0 {
            return Err(SrdError::Cipher);
        }

        // Negotiate
        let mut out_msg = new_srd_initiate_msg(self.seq_num, cipher_flags, self.key_size)?;
        self.write_msg(&mut out_msg, &mut output_data)?;
        Ok(())
    }

    // Server initiate -> offer
    fn server_authenticate_0(&mut self, input_data: &[u8], mut output_data: &mut Vec<u8>) -> Result<()> {
        let input_msg = self.read_msg(input_data)?;

        match input_msg {
            SrdMessage::Initiate(_hdr, initiate) => {
                // Negotiate
                self.set_key_size(initiate.key_size())?;
                self.find_dh_parameters()?;

                let key_size = initiate.key_size();

                let mut private_key_bytes = vec![0u8; self.key_size as usize];
                fill_random(&mut private_key_bytes)?;

                // Challenge
                self.private_key = BigUint::from_bytes_be(&private_key_bytes);
                let public_key = self.generator.modpow(&self.private_key, &self.prime);
                fill_random(&mut self.server_nonce)?;

                let mut cipher_flags = 0u32;
                for c in &self.supported_ciphers {
                    cipher_flags |= c.flag();
                }

                if cipher_flags == 0 {
                    return Err(SrdError::Cipher);
                }

                let mut out_msg = new_srd_offer_msg(
                    self.seq_num,
                    cipher_flags,
                    key_size,
                    self.generator.to_bytes_be(),
                    self.prime.to_bytes_be(),
                    public_key.to_bytes_be(),
                    self.server_nonce,
                );

                self.write_msg(&mut out_msg, &mut output_data)?;

                Ok(())
            }
            _ => {
                return Err(SrdError::BadSequence);
            }
        }
    }

    // Client offer -> accept
    fn client_authenticate_1(&mut self, input_data: &[u8], mut output_data: &mut Vec<u8>) -> Result<()> {
        //Challenge
        let input_msg = self.read_msg(input_data)?;
        match input_msg {
            SrdMessage::Offer(_hdr, offer) => {
                let server_ciphers = Cipher::from_flags(offer.ciphers);

                self.generator = BigUint::from_bytes_be(&offer.generator);
                self.prime = BigUint::from_bytes_be(&offer.prime);

                let mut private_key_bytes = vec![0u8; self.key_size as usize];

                fill_random(&mut private_key_bytes)?;

                self.private_key = BigUint::from_bytes_be(&private_key_bytes);

                let public_key = self.generator.modpow(&self.private_key, &self.prime);

                fill_random(&mut self.server_nonce)?;

                self.server_nonce = offer.nonce;
                self.secret_key = BigUint::from_bytes_be(&offer.public_key)
                    .modpow(&self.private_key, &self.prime)
                    .to_bytes_be();

                self.derive_keys();

                let key_size = offer.key_size();

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

                // Accept
                let mut common_ciphers = Vec::new();
                for c in &server_ciphers {
                    if self.supported_ciphers.contains(c) {
                        common_ciphers.push(*c);
                    }
                }

                self.cipher = Cipher::best_cipher(&common_ciphers)?;

                let mut out_msg = new_srd_accept_msg(
                    self.seq_num,
                    self.cipher.flag(),
                    key_size,
                    public_key.to_bytes_be(),
                    self.client_nonce,
                    cbt,
                );

                self.write_msg(&mut out_msg, &mut output_data)?;

                Ok(())
            }
            _ => {
                return Err(SrdError::BadSequence);
            }
        }
    }

    // Server accept -> confirm
    fn server_authenticate_1(&mut self, input_data: &[u8], mut output_data: &mut Vec<u8>) -> Result<()> {
        // Response

        let message = self.read_msg(input_data)?;
        match &message {
            SrdMessage::Accept(hdr, accept) => {
                let chosen_cipher = Cipher::from_flags(accept.cipher);

                if chosen_cipher.len() != 1 {
                    return Err(SrdError::Cipher);
                }

                self.cipher = *chosen_cipher.get(0).unwrap_or(&Cipher::XChaCha20);

                if !self.supported_ciphers.contains(&self.cipher) {
                    return Err(SrdError::Cipher);
                }

                self.client_nonce = accept.nonce;

                self.secret_key = BigUint::from_bytes_be(&accept.public_key)
                    .modpow(&self.private_key, &self.prime)
                    .to_bytes_be();

                self.derive_keys();

                // Integrety_key has been generated. We has to verify the mac here.
                self.validate_mac(&message)?;

                // Verify client cbt
                match self.cert_data {
                    None => {
                        if hdr.has_cbt() {
                            return Err(SrdError::InvalidCert);
                        }
                    }
                    Some(ref c) => {
                        if !hdr.has_cbt() {
                            return Err(SrdError::InvalidCert);
                        }
                        let mut hmac = Hmac::<Sha256>::new_varkey(&self.integrity_key)?;

                        hmac.input(&self.client_nonce);
                        hmac.input(&c);

                        let mut cbt_data: [u8; 32] = [0u8; 32];
                        hmac.result().code().to_vec().write_all(&mut cbt_data)?;
                        if cbt_data != accept.cbt {
                            return Err(SrdError::InvalidCbt);
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

                let mut out_msg = new_srd_confirm_msg(self.seq_num, cbt);

                self.write_msg(&mut out_msg, &mut output_data)?;
                Ok(())
            }
            _ => {
                return Err(SrdError::BadSequence);
            }
        }
    }

    // Client confirm -> delegate
    fn client_authenticate_2(&mut self, input_data: &[u8], mut output_data: &mut Vec<u8>) -> Result<()> {
        // Confirm
        let input_msg = self.read_msg(input_data)?;
        match input_msg {
            SrdMessage::Confirm(hdr, confirm) => {
                // Verify Server cbt
                match self.cert_data {
                    None => {
                        if hdr.has_cbt() {
                            return Err(SrdError::InvalidCert);
                        }
                    }
                    Some(ref c) => {
                        if !hdr.has_cbt() {
                            return Err(SrdError::InvalidCert);
                        }
                        let mut hmac = Hmac::<Sha256>::new_varkey(&self.integrity_key)?;

                        hmac.input(&self.server_nonce);
                        hmac.input(&c);

                        let mut cbt_data: [u8; 32] = [0u8; 32];
                        hmac.result().code().to_vec().write_all(&mut cbt_data)?;
                        if cbt_data != confirm.cbt {
                            return Err(SrdError::InvalidCbt);
                        }
                    }
                }

                let mut out_msg = match self.blob {
                    None => {
                        return Err(SrdError::MissingBlob);
                    }
                    Some(ref b) => new_srd_delegate_msg(self.seq_num, b, self.cipher, &self.delegation_key, &self.iv)?,
                };

                self.write_msg(&mut out_msg, &mut output_data)?;
                Ok(())
            }
            _ => {
                return Err(SrdError::BadSequence);
            }
        }
    }

    // Server delegate -> result
    fn server_authenticate_2(&mut self, input_data: &[u8]) -> Result<()> {
        // Receive delegate and verify credentials...
        let input_msg = self.read_msg(input_data)?;
        match input_msg {
            SrdMessage::Delegate(_hdr, delegate) => {
                self.blob = Some(delegate.get_data(self.cipher, &self.delegation_key, &self.iv)?);

                Ok(())
            }
            _ => {
                return Err(SrdError::BadSequence);
            }
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
            _ => Err(SrdError::InvalidKeySize),
        }
    }

    fn derive_keys(&mut self) {
        let mut hash = Sha256::new();
        hash.input(&self.client_nonce);
        hash.input(&self.secret_key);
        hash.input(&self.server_nonce);

        self.delegation_key.clone_from_slice(&hash.result().to_vec());

        hash = Sha256::new();
        hash.input(&self.server_nonce);
        hash.input(&self.secret_key);
        hash.input(&self.client_nonce);

        self.integrity_key.clone_from_slice(&hash.result().to_vec());

        hash = Sha256::new();
        hash.input(&self.client_nonce);
        hash.input(&self.server_nonce);

        self.iv.clone_from_slice(&hash.result().to_vec());
    }
}

#[cfg(feature = "wasm")]
pub fn fill_random(data: &mut [u8]) -> Result<()> {
    let mut new_data = getrandom(data.to_vec());
    new_data.write(data)?;
    Ok(())
}

#[cfg(not(feature = "wasm"))]
pub fn fill_random(data: &mut [u8]) -> Result<()> {
    EntropyRng::new().try_fill_bytes(data)?;
    Ok(())
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
extern "C" {
    // For WebAssembly, you must bind your own rng or else it will fail. This will eventually be done automatically by the rand crate.
    fn getrandom(v: Vec<u8>) -> Vec<u8>;
}
