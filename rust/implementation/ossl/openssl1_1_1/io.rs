// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! OpenSSL I/O implementation.
//!
//! This module defines the I/O implementation for OpenSSL, based on a
//! custom BIO_METHOD.

use openssl1_1_1 as openssl;

use crate::implementation::ossl;
use crate::io::error::IntoIOError;

use super::Ossl;

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
fn get_bio_ssl(bio: *mut openssl::bio_st) -> Result<*mut openssl::SSL, i64> {
    let mut ssl: *mut openssl::SSL = std::ptr::null_mut();
    let e = unsafe {
        // Bindgen can't parse function macros, so we use OpenSSL's internal API instead of the public API.
        // openssl::BIO_get_ssl(bio, &mut ssl as *mut *mut openssl::SSL)
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

/// Returns the tunnel from a BIO.
fn get_tunnel_from_bio<'a>(bio: *mut openssl::bio_st) -> &'a mut ossl::OsslTunnel<'a, Ossl> {
    let tun = unsafe { &mut *(openssl::BIO_get_data(bio) as *mut ossl::OsslTunnel<Ossl>) };
    debug_assert!(tun.bio.as_ptr() == bio);
    tun
}

/// BIO write callback.
unsafe extern "C" fn bio_write(
    bio: *mut openssl::bio_st,
    data: *const std::os::raw::c_char,
    len: usize,
    written: *mut usize,
) -> i32 {
    clear_bio_retry_flags(bio);
    let tun = get_tunnel_from_bio(bio);

    if tun.state != pb::State::STATE_HANDSHAKE_DONE {
        if let Ok(ssl) = get_bio_ssl(bio) {
            debug_assert!(tun.ssl.as_nonnull().as_ptr() == ssl);
            if openssl::SSL_get_state(ssl) == openssl::OSSL_HANDSHAKE_STATE_TLS_ST_OK {
                tun.state = pb::State::STATE_HANDSHAKE_DONE;
            }
        }
    }

    (tun.io).set_state(tun.state);
    (tun.io)
        .write(std::slice::from_raw_parts(data.cast(), len))
        .map(|n| {
            *written = n;
            1
        })
        .unwrap_or_else(|e| match e.into_io_error() {
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
    data: *mut std::os::raw::c_char,
    len: usize,
    read: *mut usize,
) -> i32 {
    clear_bio_retry_flags(bio);
    let tun = get_tunnel_from_bio(bio);

    if tun.state != pb::State::STATE_HANDSHAKE_DONE {
        if let Ok(ssl) = get_bio_ssl(bio) {
            debug_assert!(tun.ssl.as_nonnull().as_ptr() == ssl);
            if openssl::SSL_get_state(ssl) == openssl::OSSL_HANDSHAKE_STATE_TLS_ST_OK {
                tun.state = pb::State::STATE_HANDSHAKE_DONE;
            }
        }
    }
    (tun.io).set_state(tun.state);
    (tun.io)
        .read(std::slice::from_raw_parts_mut(data.cast(), len))
        .map(|n| {
            *read = n;
            1
        })
        .unwrap_or_else(|e| match e.into_io_error() {
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
        openssl::BIO_CTRL_FLUSH => {
            let tun = get_tunnel_from_bio(bio);
            (tun.io).flush().map(|_| 1).unwrap_or(0)
        }
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
