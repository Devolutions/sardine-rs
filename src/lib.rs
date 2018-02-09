extern crate rand;
extern crate num;
extern crate crypto;
extern crate byteorder;

mod now_auth_srd;

#[test]
fn simple_test() {
    let context: now_auth_srd::NowSrd = now_auth_srd::NowSrd{
        server: false,
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

        generator: [0; 2]
    };

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
    let packet_type:u8 = 1;
    assert_eq!(now_auth_srd::now_srd_read_msg(&context, &msg, packet_type), 10 );
}