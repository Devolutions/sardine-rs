extern crate byteorder;
extern crate crypto;
extern crate num;
extern crate rand;

mod now_auth_srd;

#[test]
fn simple_test() {
    let msg: now_auth_srd::NowAuthSrdMessage = now_auth_srd::NowAuthSrdMessage {
        header: now_auth_srd::NowAuthSrdHeader {
            packet_type: 1,
            flags: 0,
        },
        payload: now_auth_srd::NowAuthSrdPayload::NowAuthSrdNegotiate(
            now_auth_srd::NowAuthSrdNegotiate {
                key_size: 0,
                reserved: 0,
            },
        ),
    };

    let mut buffer: Vec<u8> = Vec::new();
    let srd: now_auth_srd::NowSrd = now_auth_srd::NowSrd::new(false);

    srd.now_srd_write_msg(&msg, &mut buffer);

    assert_eq!(buffer, [1, 0, 0, 0, 0, 0, 0, 0]);
    println!("{:?}", buffer);
    //assert_eq!(srd.now_srd_read_msg(&msg, 1), 10);
    //assert_eq!(srd.now_srd_read_msg(&msg, 0), -1);
}
