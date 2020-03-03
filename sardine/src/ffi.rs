#![allow(non_snake_case)]

extern crate libc;

use srd::fill_random;
use srd::Srd;
use blobs::SrdBlob;

use std;
use std::ptr::copy_nonoverlapping;
use std::slice;

#[no_mangle]
pub extern "C" fn Srd_New(is_server: bool, skip_delegation: bool) -> *mut Srd {
    Box::into_raw(Box::new(Srd::new(is_server, skip_delegation))) as *mut Srd
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

const IV_LEN: usize = 32;

#[no_mangle]
pub extern "C" fn Srd_Encrypt(
    srd_handle: *mut Srd,
    data: *const u8, 
    data_size: usize, 
    output: *mut u8, 
    output_size: *mut usize
) -> i32 {
    let srd = unsafe { &mut *srd_handle };
    let key = srd.get_delegation_key();

    if key.iter().all(|&x| x == 0) {
        return -1
    }

    if (data_size % 16) != 0 {
        return -1
    }

    if output_size.is_null() {
        return -1
    }

    let available_len = unsafe { *output_size };
    let required_len: usize = IV_LEN + data_size;

    if available_len < required_len || output.is_null() {
        unsafe { *output_size = required_len };
        return 0
    }

    let mut iv = [0u8; IV_LEN];
    if fill_random(&mut iv).is_err() {
        return -1
    }

    let data = unsafe { slice::from_raw_parts(data, data_size) };
    
    if let Ok(encrypted_data) = srd.get_cipher().encrypt_data(&data, key.as_slice(), &iv) {
        unsafe {
            copy_nonoverlapping(iv.as_ptr(), output, IV_LEN);
            copy_nonoverlapping(encrypted_data.as_ptr(), output.offset(IV_LEN as isize), data_size);
            *output_size = required_len;
        }

        return 1
    }

    return -1
}

#[no_mangle]
pub extern "C" fn Srd_Decrypt(
    srd_handle: *mut Srd,
    data: *const u8, 
    data_size: usize, 
    output: *mut u8, 
    output_size: *mut usize
) -> i32 {
    let srd = unsafe { &mut *srd_handle };
    let key = srd.get_delegation_key();

    if key.iter().all(|&x| x == 0) {
        return -1
    }

    if data_size < 32 {
        return -1
    }

    if output_size.is_null() {
        return -1
    }
    
    let available_len = unsafe { *output_size };
    let required_len: usize = data_size - IV_LEN;

    if available_len < required_len || output.is_null() {
        unsafe { *output_size = required_len };
        return 0
    }

    let data = unsafe { slice::from_raw_parts(data, data_size) };
    let iv = &data[0..IV_LEN];

    if let Ok(decrypted_data) = srd.get_cipher().decrypt_data(&data[IV_LEN..], key.as_slice(), &iv) {
        unsafe {
            copy_nonoverlapping(decrypted_data.as_ptr(), output, required_len);
            *output_size = required_len;
        }
    }

    return -1
}