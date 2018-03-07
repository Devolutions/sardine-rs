extern crate byteorder;
extern crate crypto;
extern crate num;
extern crate rand;

mod now_auth_srd;

use now_auth_srd::NowAuthSrdMessage;

#[test]
fn simple_test() {
    let msg: now_auth_srd::NowAuthSrdNegotiate = now_auth_srd::NowAuthSrdNegotiate {
        packet_type: 1,
        flags: 256,
        key_size: 2,
        reserved: 257,
    };

    let mut buffer: Vec<u8> = Vec::new();
    let srd: now_auth_srd::NowSrd = now_auth_srd::NowSrd::new(false);

    srd.now_srd_write_msg(&msg, &mut buffer);
    assert_eq!(buffer, [1, 0, 0, 1, 2, 0, 1, 1]);

    let decoded_msg: now_auth_srd::NowAuthSrdNegotiate =
        now_auth_srd::NowAuthSrdNegotiate::read_from(&buffer).unwrap();

    assert_eq!(decoded_msg.packet_type, 1);
    assert_eq!(decoded_msg.flags, 256);
    assert_eq!(decoded_msg.key_size, 2);
    assert_eq!(decoded_msg.reserved, 257);

    println!("{:?}", buffer);
    //assert_eq!(srd.now_srd_read_msg(&msg, 1), 10);
    //assert_eq!(srd.now_srd_read_msg(&msg, 0), -1);
}
