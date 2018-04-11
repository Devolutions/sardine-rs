use std;
use message_types::*;
use message_types::srd_id::*;

#[test]
fn negotiate_encoding() {
    let msg = SrdNegotiate {
        packet_type: 1,
        flags: 256,
        key_size: 2,
        reserved: 257,
    };

    assert_eq!(msg.get_id(), SRD_NEGOTIATE_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    assert_eq!(buffer, [1, 0, 0, 1, 2, 0, 1, 1]);
    assert_eq!(buffer.len(), msg.get_size());

    let mut cursor = std::io::Cursor::new(buffer);

    match SrdNegotiate::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.packet_type, 1);
            assert_eq!(x.flags, 256);
            assert_eq!(x.key_size, 2);
            assert_eq!(x.reserved, 257);
        }
        Err(_) => assert!(false),
    };
}

#[test]
fn challenge_encoding() {
    let msg = SrdChallenge {
        packet_type: 2,
        flags: 0,
        key_size: 256,
        generator: vec![0, 0],
        prime: vec![0u8; 256],
        public_key: vec![0u8; 256],
        nonce: [0u8; 32],
    };

    assert_eq!(msg.get_id(), SRD_CHALLENGE_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut expected = vec![2, 0, 0, 0, 0, 1, 0, 0];
    expected.append(&mut vec![0u8; 544]);

    assert_eq!(buffer, expected);
    assert_eq!(buffer.len(), msg.get_size());

    let mut cursor = std::io::Cursor::new(buffer);

    match SrdChallenge::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.packet_type, 2);
            assert_eq!(x.flags, 0);
            assert_eq!(x.key_size, 256);
            assert_eq!(x.generator, [0, 0]);
            assert_eq!(x.prime, vec![0u8; 256]);
            assert_eq!(x.public_key, vec![0u8; 256]);
            assert_eq!(x.nonce, [0u8; 32]);
        }
        Err(_) => assert!(false),
    };
}

#[test]
fn response_encoding() {
    let msg = SrdResponse {
        packet_type: 3,
        flags: 0,
        key_size: 256,
        reserved: 0,
        public_key: vec![0u8; 256],
        nonce: [0u8; 32],
        cbt: [0u8; 32],
        mac: [0u8; 32],
    };

    assert_eq!(msg.get_id(), SRD_RESPONSE_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut expected = vec![3, 0, 0, 0, 0, 1, 0, 0];
    expected.append(&mut vec![0u8; 352]);

    assert_eq!(buffer, expected);
    assert_eq!(buffer.len(), msg.get_size());

    let mut cursor = std::io::Cursor::new(buffer);

    match SrdResponse::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.packet_type, 3);
            assert_eq!(x.flags, 0);
            assert_eq!(x.key_size, 256);
            assert_eq!(x.reserved, 0);
            assert_eq!(x.public_key, vec![0u8; 256]);
            assert_eq!(x.nonce, [0u8; 32]);
            assert_eq!(x.cbt, [0u8; 32]);
            assert_eq!(x.mac, [0u8; 32]);
        }
        Err(_) => assert!(false),
    };
}

#[test]
fn confirm_encoding() {
    let msg = SrdConfirm {
        packet_type: 4,
        flags: 0,
        reserved: 0,
        cbt: [0u8; 32],
        mac: [0u8; 32],
    };

    assert_eq!(msg.get_id(), SRD_CONFIRM_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut expected = vec![4, 0, 0, 0, 0, 0, 0, 0];
    expected.append(&mut vec![0u8; 64]);

    assert_eq!(buffer, expected);
    assert_eq!(buffer.len(), msg.get_size());

    let mut cursor = std::io::Cursor::new(buffer);

    match SrdConfirm::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.packet_type, 4);
            assert_eq!(x.flags, 0);
            assert_eq!(x.reserved, 0);
            assert_eq!(x.cbt, [0u8; 32]);
            assert_eq!(x.mac, [0u8; 32]);
        }
        Err(_) => assert!(false),
    };
}

#[test]
fn delegate_encoding() {
    let blob = SrdLogonBlob {
        packet_type: 1,
        flags: 0,
        size: 256,
        data: [0u8; 256],
    };

    let msg = SrdDelegate {
        packet_type: 5,
        flags: 0,
        reserved: 0,
        blob,
        mac: [0u8; 32],
    };

    assert_eq!(msg.blob.get_id(), SRD_LOGON_BLOB_ID);
    assert_eq!(msg.get_id(), SRD_DELEGATE_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut expected = vec![5, 0, 0, 0, 0, 0, 0, 0];
    expected.append(&mut vec![1, 0, 0, 1]);
    expected.append(&mut vec![0u8; 256]);
    expected.append(&mut vec![0u8; 32]);

    assert_eq!(buffer, expected);
    assert_eq!(buffer.len(), msg.get_size());

    let mut cursor = std::io::Cursor::new(buffer);

    match SrdDelegate::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.packet_type, 5);
            assert_eq!(x.flags, 0);
            assert_eq!(x.reserved, 0);
            assert_eq!(x.blob.packet_type, 1);
            assert_eq!(x.blob.size, 256);
            assert_eq!(x.blob.data.to_vec(), vec![0u8; 256]);
            assert_eq!(x.mac, [0u8; 32]);
        }
        Err(_) => assert!(false),
    };
}

#[test]
fn result_encoding() {
    let msg = SrdResult {
        packet_type: 6,
        flags: 0,
        reserved: 0,
        status: 0,
        mac: [0u8; 32],
    };

    assert_eq!(msg.get_id(), SRD_RESULT_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut expected = vec![6, 0, 0, 0, 0, 0, 0, 0];
    expected.append(&mut vec![0u8; 36]);

    assert_eq!(buffer, expected);
    assert_eq!(buffer.len(), msg.get_size());

    let mut cursor = std::io::Cursor::new(buffer);

    match SrdResult::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.packet_type, 6);
            assert_eq!(x.flags, 0);
            assert_eq!(x.reserved, 0);
            assert_eq!(x.status, 0);
            assert_eq!(x.mac, [0u8; 32]);
        }
        Err(_) => assert!(false),
    };
}
