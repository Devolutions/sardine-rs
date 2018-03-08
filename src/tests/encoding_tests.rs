use message_types::*;
use now_auth_srd::{NOW_AUTH_SRD_NEGOTIATE_ID, NOW_AUTH_SRD_CHALLENGE_ID,
                    NOW_AUTH_SRD_RESPONSE_ID};

#[test]
fn negotiate_encoding() {
    let msg = NowAuthSrdNegotiate {
        packet_type: 1,
        flags: 256,
        key_size: 2,
        reserved: 257,
    };

    assert_eq!(msg.get_id(), NOW_AUTH_SRD_NEGOTIATE_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer){
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    assert_eq!(buffer, [1, 0, 0, 1, 2, 0, 1, 1]);
    assert_eq!(buffer.len(), msg.get_size());


    match NowAuthSrdNegotiate::read_from(&buffer) {
        Ok(x) => {
            assert_eq!(x.packet_type, 1);
            assert_eq!(x.flags, 256);
            assert_eq!(x.key_size, 2);
            assert_eq!(x.reserved, 257);
        },
        Err(_) => assert!(false),
    };
}

#[test]
fn challenge_encoding() {
    let msg = NowAuthSrdChallenge {
        packet_type: 2,
        flags: 0,
        key_size: 256,
        generator: [0, 0],
        prime: vec!(0u8; 256),
        public_key: vec!(0u8; 256),
        nonce: [0u8; 32],
    };

    assert_eq!(msg.get_id(), NOW_AUTH_SRD_CHALLENGE_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer){
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut expected = vec![2, 0, 0, 0, 0, 1, 0, 0];
    expected.append(&mut vec![0u8; 544]);

    assert_eq!(buffer, expected);
    assert_eq!(buffer.len(), msg.get_size());

    match NowAuthSrdChallenge::read_from(&buffer) {
        Ok(x) => {
            assert_eq!(x.packet_type, 2);
            assert_eq!(x.flags, 0);
            assert_eq!(x.key_size, 256);
            assert_eq!(x.generator, [0, 0]);
            assert_eq!(x.prime, vec![0u8; 256]);
            assert_eq!(x.public_key, vec![0u8; 256]);
            assert_eq!(x.nonce, [0u8; 32]);
        },
        Err(_) => assert!(false),
    };
}

#[test]
fn response_encoding() {
    let msg = NowAuthSrdResponse {
        packet_type: 3,
        flags: 0,
        key_size: 256,
        reserved: 0,
        public_key: vec!(0u8; 256),
        nonce: [0u8; 32],
        cbt: [0u8; 32],
        mac: [0u8; 32],
    };

    assert_eq!(msg.get_id(), NOW_AUTH_SRD_RESPONSE_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer){
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut expected = vec![3, 0, 0, 0, 0, 1, 0, 0];
    expected.append(&mut vec![0u8; 352]);

    assert_eq!(buffer, expected);
    assert_eq!(buffer.len(), msg.get_size());

    match NowAuthSrdResponse::read_from(&buffer) {
        Ok(x) => {
            assert_eq!(x.packet_type, 3);
            assert_eq!(x.flags, 0);
            assert_eq!(x.key_size, 256);
            assert_eq!(x.reserved, 0);
            assert_eq!(x.public_key, vec![0u8; 256]);
            assert_eq!(x.nonce, [0u8; 32]);
            assert_eq!(x.cbt, [0u8; 32]);
            assert_eq!(x.mac, [0u8; 32]);
        },
        Err(_) => assert!(false),
    };
}