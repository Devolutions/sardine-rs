use message_types::NowAuthSrdMessage;
use message_types::NowAuthSrdNegotiate;

#[test]
fn negotiate_encoding() {
    let msg: NowAuthSrdNegotiate = NowAuthSrdNegotiate {
        packet_type: 1,
        flags: 256,
        key_size: 2,
        reserved: 257,
    };

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer){
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    assert_eq!(buffer, [1, 0, 0, 1, 2, 0, 1, 1]);

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

/*#[test]
fn challenge_encoding() {
    let msg: NowAuthSrdNegotiate = NowAuthSrdNegotiate {
        packet_type: 1,
        flags: 256,
        key_size: 2,
        reserved: 257,
    };

    let mut buffer: Vec<u8> = Vec::new();
    match msg.write_to(&mut buffer){
        Ok(_) => (),
        Err(_) => assert!(false),
    };

    assert_eq!(buffer, [1, 0, 0, 1, 2, 0, 1, 1]);

    match NowAuthSrdNegotiate::read_from(&buffer) {
        Ok(x) => {
            assert_eq!(x.packet_type, 1);
            assert_eq!(x.flags, 256);
            assert_eq!(x.key_size, 2);
            assert_eq!(x.reserved, 257);
        },
        Err(_) => assert!(false),
    };
}*/
