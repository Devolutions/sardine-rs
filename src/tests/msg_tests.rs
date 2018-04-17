use std;
use message_types::*;
use message_types::srd_msg_id::*;

#[test]
fn initiate_encoding() {
    let msg = SrdInitiate::new(2);
    assert_eq!(msg.get_id(), SRD_INITIATE_MSG_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut cursor = std::io::Cursor::new(buffer);
    match SrdInitiate::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.signature, SRD_SIGNATURE);
            assert_eq!(x, msg);
        }
        Err(_) => assert!(false),
    };
}

#[test]
fn offer_encoding() {
    let msg = SrdOffer::new(256, vec![0, 0], vec![0u8; 256], vec![0u8; 256], [0u8; 32]);
    assert_eq!(msg.get_id(), SRD_OFFER_MSG_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut cursor = std::io::Cursor::new(buffer);
    match SrdOffer::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.signature, SRD_SIGNATURE);
            assert_eq!(x, msg);
        }
        Err(_) => assert!(false),
    };
}

#[test]
fn accept_encoding() {
    let msg = SrdAccept::new(256, vec![0u8; 256], [0u8; 32], Some([0u8; 32]), &Vec::new(),&[0u8; 32]).unwrap();
    assert_eq!(msg.get_id(), SRD_ACCEPT_MSG_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut cursor = std::io::Cursor::new(buffer);
    match SrdAccept::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.signature, SRD_SIGNATURE);
            assert_eq!(x, msg);
        }
        Err(_) => assert!(false),
    };
}

#[test]
fn confirm_encoding() {
    let msg = SrdConfirm::new(Some([0u8; 32]), &Vec::new(),&[0u8; 32]).unwrap();
    assert_eq!(msg.get_id(), SRD_CONFIRM_MSG_ID);

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer) {
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    let mut cursor = std::io::Cursor::new(buffer);
    match SrdConfirm::read_from(&mut cursor) {
        Ok(x) => {
            assert_eq!(x.signature, SRD_SIGNATURE);
            assert_eq!(x, msg);
        }
        Err(_) => assert!(false),
    };
}

//#[test]
//fn delegate_encoding() {
//    let blob = SrdLogonBlob {
//        packet_type: 1,
//        flags: 0,
//        size: 256,
//        data: [0u8; 256],
//    };
//
//    let msg = SrdDelegate::new() {
//        packet_type: 5,
//        flags: 0,
//        reserved: 0,
//        blob,
//        mac: [0u8; 32],
//    };
//
//    assert_eq!(msg.blob.get_id(), SRD_LOGON_BLOB_ID);
//    assert_eq!(msg.get_id(), SRD_DELEGATE_ID);
//
//    let mut buffer: Vec<u8> = Vec::new();
//    match msg.write_to(&mut buffer) {
//        Ok(_) => (),
//        Err(_) => assert!(false),
//    };
//
//    let mut expected = vec![5, 0, 0, 0, 0, 0, 0, 0];
//    expected.append(&mut vec![1, 0, 0, 1]);
//    expected.append(&mut vec![0u8; 256]);
//    expected.append(&mut vec![0u8; 32]);
//
//    assert_eq!(buffer, expected);
//    assert_eq!(buffer.len(), msg.get_size());
//
//    let mut cursor = std::io::Cursor::new(buffer);
//
//    match SrdDelegate::read_from(&mut cursor) {
//        Ok(x) => {
//            assert_eq!(x.packet_type, 5);
//            assert_eq!(x.flags, 0);
//            assert_eq!(x.reserved, 0);
//            assert_eq!(x.blob.packet_type, 1);
//            assert_eq!(x.blob.size, 256);
//            assert_eq!(x.blob.data.to_vec(), vec![0u8; 256]);
//            assert_eq!(x.mac, [0u8; 32]);
//        }
//        Err(_) => assert!(false),
//    };
//}
