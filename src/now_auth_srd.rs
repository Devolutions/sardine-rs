use std;
use message_types::NowAuthSrdMessage;

pub const NOW_AUTH_SRD_NEGOTIATE_ID: u16 = 1;
pub const NOW_AUTH_SRD_CHALLENGE_ID: u16 = 2;
pub const NOW_AUTH_SRD_RESPONSE_ID: u16 = 3;
pub const NOW_AUTH_SRD_CONFIRM_ID: u16 = 4;
pub const NOW_AUTH_SRD_DELEGATE_ID: u16 = 5;
pub const NOW_AUTH_SRD_RESULT_ID: u16 = 6;

pub struct NowSrd<'a> {
    is_server: bool,
    //NowSrdCallbacks cbs;
    keys: &'a [u8],
    key_size: u16,
    seq_num: u32,
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

    status: u8, //	NowCCBigNumRef bnGenerator;

//	uint8_t* prime;
//	uint8_t* peerKey;
//	uint8_t* publicKey;
//	uint8_t* privateKey;
//	uint8_t* secretKey;
//
//	NowCCBigNumRef bnPrime;
//	NowCCBigNumRef bnPeerKey;
//	NowCCBigNumRef bnPublicKey;
//	NowCCBigNumRef bnPrivateKey;
//	NowCCBigNumRef bnSecretKey;
}

impl<'a> NowSrd<'a> {
    pub fn new(is_server: bool) -> NowSrd<'a> {
        NowSrd {
            is_server,
            keys: &[0; 32],
            key_size: 0,
            seq_num: 0,
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
            status: if is_server { 1 } else { 2 },
        }
    }

    pub fn now_srd_write_msg(
        &self,
        msg: &NowAuthSrdMessage,
        buffer: &mut Vec<u8>,
    ) -> Result<(), std::io::Error> {
        msg.write_to(buffer)?;
        Ok(())

        /*

        let header: &NowAuthSrdHeader = &msg.header;

        // Returns an error if the type is not expected
        if header.packet_type != packet_type as u16 {
            return -1;
        }

        match header.packet_type as u8 {
            NOW_AUTH_SRD_NEGOTIATE_ID => {
                //let stream = BufStream::new(header);
                let mut bytes: Vec<u8> = Vec::new();
                //let mut slice =  &bytes;
                if header.write_to(&mut bytes).is_err() {
                    return -1;
                };
                if &bytes[0..2] != b"\x01\x00" {
                    return -1;
                }
            }
            NOW_AUTH_SRD_CHALLENGE_ID => {}
            _ => {
                // Returns if the type is unknown
                return -1;
            }
        }
        10
        */
    }

    pub fn now_srd_read_msg<T>(&self, msg: &mut T, buffer: &mut Vec<u8>) -> i32
    where T: NowAuthSrdMessage{
        let mut reader: &[u8] = &buffer;
        10
        /*
        let nstatus: u32 = 0;
        let header: &NowAuthSrdHeader = &msg.header;

        // Returns an error if the type is not expected
        if header.packet_type != packet_type as u16 {
            return -1;
        }

        match header.packet_type as u8 {
            NOW_AUTH_SRD_NEGOTIATE_ID => {
                //let stream = BufStream::new(header);
                let mut bytes: Vec<u8> = Vec::new();
                //let mut slice =  &bytes;
                if header.write_to(&mut bytes).is_err() {
                    return -1;
                };
                if &bytes[0..2] != b"\x01\x00" {
                    return -1;
                }
            }
            NOW_AUTH_SRD_CHALLENGE_ID => {}
            _ => {
                // Returns if the type is unknown
                return -1;
            }
        }
        10
        */
    }
}
