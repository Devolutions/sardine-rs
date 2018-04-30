#![allow(non_snake_case)]

extern crate libc;

use std;
use srd::Srd;
use srd_blob::{SrdBlob};

#[no_mangle]
pub extern "C" fn Srd_New(is_server: bool) -> *mut Srd {
    match Srd::new(is_server) {
        Ok(srd_new) => {
            Box::into_raw(Box::new(srd_new)) as *mut Srd
        }
        Err(_) => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn Srd_Free(srd_handle: *mut Srd) {
    // Will be deleted when the srd will go out of scope
    let _srd = unsafe { Box::from_raw(srd_handle ) };
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
            }
            else {
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
pub extern "C" fn Srd_SetBlob(srd_handle: *mut Srd, blob_name: *const u8, blob_name_size: libc::c_int, blob_data: *const libc::c_uchar, blob_data_size: libc::c_int,) -> libc::c_int {
    let mut status = -1;
    let srd = unsafe { &mut *srd_handle };

    let blob_name = unsafe { std::slice::from_raw_parts::<u8>(blob_name, blob_name_size as usize) };
    let blob_data = unsafe { std::slice::from_raw_parts::<u8>(blob_data, blob_data_size as usize) };
    let blob_name_len = blob_name.len();

    // Last char has to be a null char (0)
    if blob_name_len > 0 && blob_name[blob_name_len - 1] == 0 {
        if let Ok(blob_name) = std::str::from_utf8(&blob_name[..blob_name_len-1]) {
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
        let blob_type_len = blob.blob_type.len() as i32;
        let blob_type_size = blob_type_len + 1;

        if buffer != std::ptr::null_mut() {
            if blob_type_size > buffer_size {
                return -1;
            }

            let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(buffer, buffer_size as usize) };
            buffer_data[0..blob_type_len as usize].clone_from_slice(blob.blob_type.as_ref());
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
        let blob_data_len = (blob.data.len()) as i32;

        if buffer != std::ptr::null_mut() {
            if blob_data_len > buffer_size {
                return -1;
            }

            let buffer_data = unsafe { std::slice::from_raw_parts_mut::<u8>(buffer, buffer_size as usize) };
            buffer_data.clone_from_slice(&blob.data);
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