extern crate rand;
extern crate num;
extern crate crypto;
extern crate byteorder;

mod now_auth_srd;

#[test]
fn simple_test() {

    let msg: now_auth_srd::NowAuthSrdMessage = now_auth_srd::NowAuthSrdMessage{
        header: now_auth_srd::NowAuthSrdHeader{
            packet_type: 1,
            flags: 0
        },
        payload: now_auth_srd::NowAuthSrdPayload::NowAuthSrdNegotiate(
            now_auth_srd::NowAuthSrdNegotiate{
                key_size: 0,
                reserved:0
        })
    };

    let srd: now_auth_srd::NowSrd = now_auth_srd::NowSrd::new(false);

    assert_eq!(srd.now_srd_read_msg(&msg, 1), 10 );
    assert_eq!(srd.now_srd_read_msg(&msg, 0), -1 );

}