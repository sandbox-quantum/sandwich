// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! OpenSSL I/O implementation.
//!
//! This module defines the I/O implementation for OpenSSL, based on a
//! custom BIO_METHOD.
//!
//! Author: thb-sb

/// Clears the BIO retry flag.
fn clear_bio_retry_flags(bio: *mut openssl::bio_st) {
    unsafe {
        openssl::BIO_clear_flags(
            bio,
            (openssl::BIO_FLAGS_RWS | openssl::BIO_FLAGS_SHOULD_RETRY) as i32,
        );
    }
}

/// Gets the SSL* handle from the BIO.
fn get_bio_ssl(bio: *mut openssl::bio_st) -> std::result::Result<*mut openssl::SSL, i64> {
    let mut ssl: *mut openssl::SSL = std::ptr::null_mut();
    let e = unsafe {
        openssl::BIO_ctrl(
            bio,
            openssl::BIO_C_GET_SSL as i32,
            0,
            (&mut ssl as *mut *mut openssl::SSL) as *mut std::ffi::c_void,
        )
    };
    match e {
        1 => Ok(ssl),
        _ => Err(e),
    }
}

/// Sets the retry write flag.
fn set_bio_retry_write(bio: *mut openssl::bio_st) {
    unsafe {
        openssl::BIO_set_flags(
            bio,
            (openssl::BIO_FLAGS_WRITE | openssl::BIO_FLAGS_SHOULD_RETRY) as i32,
        );
    }
}

/// Sets the retry read flag.
fn set_bio_retry_read(bio: *mut openssl::bio_st) {
    unsafe {
        openssl::BIO_set_flags(
            bio,
            (openssl::BIO_FLAGS_READ | openssl::BIO_FLAGS_SHOULD_RETRY) as i32,
        );
    }
}

/// Sets BIO as closed.
fn set_bio_close(bio: *mut openssl::bio_st) {
    unsafe {
        openssl::BIO_ctrl(
            bio,
            openssl::BIO_CTRL_SET_CLOSE as i32,
            1,
            std::ptr::null_mut(),
        );
    }
}

/// BIO write callback.
unsafe extern "C" fn bio_write(
    bio: *mut openssl::bio_st,
    data: *const i8,
    len: usize,
    written: *mut usize,
) -> i32 {
    clear_bio_retry_flags(bio);
    let tun = &mut *(openssl::BIO_get_data(bio) as *mut super::tunnel::SSLHandle);

    debug_assert!(tun.bio.as_ptr() == bio);

    if tun.state != pb::State::STATE_HANDSHAKE_DONE {
        if let Ok(ssl) = get_bio_ssl(bio) {
            debug_assert!(tun.ssl.as_ptr() == ssl);
            if openssl::SSL_get_state(ssl) == openssl::OSSL_HANDSHAKE_STATE_TLS_ST_OK {
                tun.state = pb::State::STATE_HANDSHAKE_DONE;
            }
        }
    }

    (tun.io)
        .write(
            std::slice::from_raw_parts(data as *const u8, len),
            tun.state,
        )
        .map(|n| {
            *written = n;
            1
        })
        .unwrap_or_else(|e| match e.into() {
            pb::IOError::IOERROR_IN_PROGRESS | pb::IOError::IOERROR_WOULD_BLOCK => {
                set_bio_retry_write(bio);
                -1
            }
            pb::IOError::IOERROR_CLOSED | pb::IOError::IOERROR_REFUSED => {
                set_bio_close(bio);
                -1
            }
            _ => -1,
        })
}

/// BIO read callback.
unsafe extern "C" fn bio_read(
    bio: *mut openssl::bio_st,
    data: *mut i8,
    len: usize,
    read: *mut usize,
) -> i32 {
    clear_bio_retry_flags(bio);
    let tun = &mut *(openssl::BIO_get_data(bio) as *mut super::tunnel::SSLHandle);

    debug_assert!(tun.bio.as_ptr() == bio);

    if tun.state != pb::State::STATE_HANDSHAKE_DONE {
        if let Ok(ssl) = get_bio_ssl(bio) {
            debug_assert!(tun.ssl.as_ptr() == ssl);
            if openssl::SSL_get_state(ssl) == openssl::OSSL_HANDSHAKE_STATE_TLS_ST_OK {
                tun.state = pb::State::STATE_HANDSHAKE_DONE;
            }
        }
    }

    (tun.io)
        .read(
            std::slice::from_raw_parts_mut(data as *mut u8, len),
            tun.state,
        )
        .map(|n| {
            *read = n;
            1
        })
        .unwrap_or_else(|e| match e.into() {
            pb::IOError::IOERROR_IN_PROGRESS | pb::IOError::IOERROR_WOULD_BLOCK => {
                set_bio_retry_read(bio);
                -1
            }
            pb::IOError::IOERROR_CLOSED | pb::IOError::IOERROR_REFUSED => {
                set_bio_close(bio);
                -1
            }
            _ => -1,
        })
}

/// BIO control callback.
unsafe extern "C" fn bio_ctrl(
    bio: *mut openssl::bio_st,
    cmd: i32,
    larg: i64,
    _pargs: *mut std::ffi::c_void,
) -> i64 {
    match cmd as u32 {
        openssl::BIO_CTRL_SET_CLOSE => {
            openssl::BIO_set_shutdown(bio, larg as i32);
            1
        }
        openssl::BIO_CTRL_GET_CLOSE => openssl::BIO_get_shutdown(bio) as i64,
        openssl::BIO_CTRL_FLUSH => 1,
        _ => 0,
    }
}

/// BIO create callback (never used).
unsafe extern "C" fn bio_create(_bio: *mut openssl::bio_st) -> i32 {
    1
}

/// BIO destroy callback (never used).
unsafe extern "C" fn bio_destroy(_bio: *mut openssl::bio_st) -> i32 {
    1
}

/// Static BIO method.
pub(super) const BIO_METH: openssl::bio_method_st = openssl::bio_method_st {
    type_: openssl::BIO_TYPE_SOCKET as i32,
    name: std::ptr::null_mut(),
    bwrite: Some(bio_write),
    bwrite_old: None,
    bread: Some(bio_read),
    bread_old: None,
    bputs: None,
    bgets: None,
    ctrl: Some(bio_ctrl),
    create: Some(bio_create),
    destroy: Some(bio_destroy),
    callback_ctrl: None,
};
