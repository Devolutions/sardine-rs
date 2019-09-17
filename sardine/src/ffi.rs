#![allow(non_snake_case)]

use std;
use std::convert::{Into, TryInto};
use crate::srd::{Srd, fill_random};
use crate::cipher::Cipher;
use crate::blobs::SrdBlob;
use crate::messages::Message;

#[no_mangle]
pub extern "C" fn Srd_New(is_server: bool, delegation: bool) -> *mut Srd {
    Box::into_raw(Box::new(Srd::new(is_server, delegation))) as *mut Srd
}

#[no_mangle]
pub extern "C" fn Srd_Free(srd_handle: *mut Srd) {
    // Will be deleted when the srd will go out of scope
    let _srd = unsafe { Box::from_raw(srd_handle) };
}

#[no_mangle]
pub extern "C" fn Srd_Input(srd_handle: *mut Srd, buffer: *const u8, buffer_size: libc::c_int) -> libc::c_int {
    let srd = unsafe { &mut *srd_handle };

    let input_data = unsafe { std::slice::from_raw_parts::<u8>(buffer, buffer_size as usize) };
    let mut output_data = Vec::new();

    match srd.authenticate(&input_data, &mut output_data) {
        Ok(is_finished) => {
            srd.set_output_data(output_data);
            if is_finished {
                return 0;
            } else {
                return 1;
            }
        }
        Err(_) => {
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn Srd_Output(srd_handle: *mut Srd, buffer: *mut u8, buffer_size: libc::c_int) -> libc::c_int {
    let srd = unsafe { &mut *srd_handle };

    if let &Some(ref output_data) = srd.get_output_data() {
        let output_size = output_data.len() as i32;

        if buffer != std::ptr::null_mut() {
            if output_size > buffer_size {
                return -1;
            }

            let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(buffer, buffer_size as usize) };
            buffer_data.clone_from_slice(&output_data);
        }
        return output_size;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn Srd_SetBlob(
    srd_handle: *mut Srd,
    blob_name: *const u8,
    blob_name_size: libc::c_int,
    blob_data: *const libc::c_uchar,
    blob_data_size: libc::c_int,
) -> libc::c_int {
    let mut status = -1;
    let srd = unsafe { &mut *srd_handle };

    let blob_name = unsafe { std::slice::from_raw_parts::<u8>(blob_name, blob_name_size as usize) };
    let blob_data = unsafe { std::slice::from_raw_parts::<u8>(blob_data, blob_data_size as usize) };
    let blob_name_len = blob_name.len();

    // Last char has to be a null char (0)
    if blob_name_len > 0 && blob_name[blob_name_len - 1] == 0 {
        if let Ok(blob_name) = std::str::from_utf8(&blob_name[..blob_name_len - 1]) {
            srd.set_raw_blob(SrdBlob::new(&blob_name, blob_data));
            status = 1;
        }
    }

    return status;
}

#[no_mangle]
pub extern "C" fn Srd_GetBlobName(srd_handle: *mut Srd, buffer: *mut u8, buffer_size: libc::c_int) -> libc::c_int {
    let srd = unsafe { &mut *srd_handle };

    if let Some(blob) = srd.get_raw_blob() {
        let blob_type_len = blob.blob_type().len() as i32;
        let blob_type_size = blob_type_len + 1;

        if buffer != std::ptr::null_mut() {
            if blob_type_size > buffer_size {
                return -1;
            }

            let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(buffer, buffer_size as usize) };
            buffer_data[0..blob_type_len as usize].clone_from_slice(blob.blob_type().as_ref());
            buffer_data[blob_type_len as usize] = 0;
        }

        return blob_type_size;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn Srd_GetBlobData(srd_handle: *mut Srd, buffer: *mut u8, buffer_size: libc::c_int) -> libc::c_int {
    let srd = unsafe { &mut *srd_handle };

    if let Some(blob) = srd.get_raw_blob() {
        let blob_data_len = (blob.data().len()) as i32;

        if buffer != std::ptr::null_mut() {
            if blob_data_len > buffer_size {
                return -1;
            }

            let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(buffer, buffer_size as usize) };
            buffer_data.clone_from_slice(&blob.data());
        }

        return blob_data_len;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn Srd_SetCertData(srd_handle: *mut Srd, data: *const u8, data_size: libc::c_int) -> libc::c_int {
    let srd = unsafe { &mut *srd_handle };
    let cert_data = unsafe { std::slice::from_raw_parts::<u8>(data, data_size as usize) };

    match srd.set_cert_data(Vec::from(cert_data)) {
        Ok(_) => 1,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn Srd_GetDelegationKey(srd_handle: *mut Srd, buffer: *mut u8, buffer_size: libc::c_int) -> libc::c_int {
    let srd = unsafe { &mut *srd_handle };

    let key = srd.get_delegation_key();
    let size = key.len() as i32;

    if buffer != std::ptr::null_mut() {
        if size > buffer_size {
            return -1;
        }

        let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(buffer, buffer_size as usize) };
        buffer_data.clone_from_slice(&key);
    }

    return size;
}

#[no_mangle]
pub extern "C" fn Srd_GetIntegrityKey(srd_handle: *mut Srd, buffer: *mut u8, buffer_size: libc::c_int) -> libc::c_int {
    let srd = unsafe { &mut *srd_handle };

    let key = srd.get_integrity_key();
    let size = key.len() as i32;

    if buffer != std::ptr::null_mut() {
        if size > buffer_size {
            return -1;
        }

        let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(buffer, buffer_size as usize) };
        buffer_data.clone_from_slice(&key);
    }

    return size;
}

#[no_mangle]
pub extern "C" fn Srd_GetCipher(srd_handle: *mut Srd) -> libc::c_int {
    let srd = unsafe { &mut *srd_handle };

    let cipher: u32 = srd.get_cipher().into();

    return cipher as i32;
}

#[no_mangle]
pub extern "C" fn SrdBlob_New(blob_name: *const u8,
                              blob_name_size: libc::c_int,
                              blob_data: *const libc::c_uchar,
                              blob_data_size: libc::c_int) -> *mut SrdBlob {

    let blob_name = unsafe { std::slice::from_raw_parts::<u8>(blob_name, blob_name_size as usize) };
    let blob_data = unsafe { std::slice::from_raw_parts::<u8>(blob_data, blob_data_size as usize) };
    let blob_name_len = blob_name.len();

    // Last char has to be a null char (0)
    if blob_name_len > 0 && blob_name[blob_name_len - 1] == 0 {
        if let Ok(blob_name) = std::str::from_utf8(&blob_name[..blob_name_len - 1]) {
            return Box::into_raw(Box::new(SrdBlob::new(&blob_name, blob_data))) as *mut SrdBlob;
        }
    }

    return std::ptr::null_mut::<SrdBlob>();
}

#[no_mangle]
pub extern "C" fn SrdBlob_Free(srd_blob_handle: *mut SrdBlob) {
    unsafe { Box::from_raw(srd_blob_handle) };
}

#[no_mangle]
pub extern "C" fn SrdBlob_GetName(srd_blob_handle: *mut SrdBlob, output: *mut u8, output_size: libc::c_int) -> libc::c_int {
    let srd_blob = unsafe { &mut *srd_blob_handle };

    let blob_type_len = srd_blob.blob_type().len() as i32;
    let output_len = blob_type_len + 1;

    if output != std::ptr::null_mut() {
        if output_len > output_size {
            return -1;
        }

        let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(output, output_size as usize) };
        buffer_data[0..blob_type_len as usize].clone_from_slice(srd_blob.blob_type().as_ref());
        buffer_data[blob_type_len as usize] = 0;
    }

    return output_len;
}

#[no_mangle]
pub extern "C" fn SrdBlob_GetData(srd_blob_handle: *mut SrdBlob, output: *mut u8, output_size: libc::c_int) -> libc::c_int {
    let srd_blob = unsafe { &mut *srd_blob_handle };

    let output_len = (srd_blob.data().len()) as i32;

    if output != std::ptr::null_mut() {
        if output_len > output_size {
            return -1;
        }

        let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(output, output_len as usize) };
        buffer_data.clone_from_slice(&srd_blob.data());
    }

    return output_len;
}

#[no_mangle]
pub extern "C" fn SrdBlob_Encrypt(srd_blob_handle: *mut SrdBlob,
                                  cipher: i32,
                                  key: *mut u8,
                                  key_size: libc::c_int,
                                  output: *mut u8,
                                  output_size: libc::c_int) -> libc::c_int {

    let srd_blob = unsafe { &mut *srd_blob_handle };
    let cipher_result: Result<Cipher, ()> = (cipher as u32).try_into();

    if let Ok(cipher) = cipher_result {
        let mut data_to_encrypt = Vec::new();

        if let Err(_) = srd_blob.write_to(&mut data_to_encrypt) {
            return -1;
        }

        let output_len = (data_to_encrypt.len() + 32) as i32; // 32 is for the iv added at the beginning of the encrypted data

        if output != std::ptr::null_mut() {
            if output_len > output_size {
                return -1;
            }

            let delegated_key = unsafe { std::slice::from_raw_parts::<u8>(key, key_size as usize) };
            let mut iv = vec![0u8; 32];

            if let Ok(_) = fill_random(&mut iv) {
                if let Ok(mut encrypted_data) = cipher.encrypt_data(&data_to_encrypt, &delegated_key, &iv) {
                    iv.append(&mut encrypted_data);

                    let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(output, output_len as usize) };
                    buffer_data.clone_from_slice(&iv);
                } else {
                    return -1;
                }
            } else {
                return -1;
            }
        }

        return output_len;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn SrdBlob_Decrypt(cipher: i32,
                                  key: *mut u8,
                                  key_size: libc::c_int,
                                  data: *const u8,
                                  data_size: libc::c_int) -> *mut SrdBlob {

    let cipher_result: Result<Cipher, ()> = (cipher as u32).try_into();

    if let Ok(cipher) = cipher_result {
        let delegated_key = unsafe { std::slice::from_raw_parts::<u8>(key, key_size as usize) };
        let buffer = unsafe { std::slice::from_raw_parts::<u8>(data, data_size as usize) };

        if buffer.len() > 32 {
            let iv = &buffer[0..32];
            let data_to_decrypt = &buffer[32..];
            if let Ok(decrypted_data) = cipher.decrypt_data(&data_to_decrypt, &delegated_key, &iv) {
                let mut cursor = std::io::Cursor::new(decrypted_data);

                if let Ok(srd_blob) = SrdBlob::read_from(&mut cursor) {
                    return Box::into_raw(Box::new(srd_blob)) as *mut SrdBlob;
                }
            }
        }
    }
    return std::ptr::null_mut::<SrdBlob>();;
}

