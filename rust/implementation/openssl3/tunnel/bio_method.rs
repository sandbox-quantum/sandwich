// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Implementation of the Sandwich BIO method.

use std::ffi::{c_char, c_int, c_void};
use std::ptr::{self, NonNull};

use crate::io::error::IntoIOError;
use crate::ossl3::support;

use support::{NativeBio, NativeSsl};

use super::Tunnel;

/// A wrapper around a BIO.
struct Bio(NonNull<NativeBio>);

impl std::fmt::Debug for Bio {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SandwichOpenSSL3BIO({:p})", self.0.as_ptr())
    }
}

impl Bio {
    /// Clears the BIO retry flag.
    fn clear_retry_flag(&self) {
        self.clear_flags((openssl3::BIO_FLAGS_RWS | openssl3::BIO_FLAGS_SHOULD_RETRY) as c_int);
    }

    /// Sets the 'retry read' flag.
    fn set_retry_read_flag(&self) {
        self.set_flags((openssl3::BIO_FLAGS_READ | openssl3::BIO_FLAGS_SHOULD_RETRY) as c_int);
    }

    /// Sets the 'retry write' flag.
    fn set_retry_write_flag(&self) {
        self.set_flags((openssl3::BIO_FLAGS_WRITE | openssl3::BIO_FLAGS_SHOULD_RETRY) as c_int);
    }

    /// Declares the BIO as closed.
    fn declare_closed(&self) {
        // `BIO_set_close` is a C macro.
        unsafe {
            openssl3::BIO_ctrl(
                self.0.as_ptr(),
                openssl3::BIO_CTRL_SET_CLOSE as c_int,
                1,
                ptr::null_mut(),
            )
        };
    }

    /// Clears flags.
    fn clear_flags(&self, flags: impl Into<c_int>) {
        unsafe { openssl3::BIO_clear_flags(self.0.as_ptr(), flags.into()) };
    }

    /// Sets flags.
    fn set_flags(&self, flags: impl Into<c_int>) {
        unsafe { openssl3::BIO_set_flags(self.0.as_ptr(), flags.into()) };
    }

    /// Returns the tunnel attached to the BIO.
    fn get_tunnel<'a>(&self) -> Option<&'a mut Tunnel<'a>> {
        NonNull::new(unsafe { openssl3::BIO_get_data(self.0.as_ptr()) }.cast::<Tunnel<'a>>())
            .map(|mut p| unsafe { p.as_mut() })
    }

    /// Returns the SSL object attached to the BIO.
    fn get_ssl(&self) -> Result<NonNull<NativeSsl>, pb::IOError> {
        let mut ssl = ptr::null_mut::<NativeSsl>();
        if unsafe {
            // `BIO_get_ssl` is a C macro.
            openssl3::BIO_ctrl(
                self.0.as_ptr(),
                openssl3::BIO_C_GET_SSL as c_int,
                0,
                (&mut ssl as *mut *mut NativeSsl).cast(),
            )
        } == 1
        {
            Ok(unsafe { NonNull::new_unchecked(ssl) })
        } else {
            Err(pb::IOError::IOERROR_SYSTEM_ERROR)
        }
    }

    /// Synchronizes the SSL state with the tunnel state.
    fn synchronize_states(&self, tun: &'_ mut Tunnel<'_>) {
        if tun.state != pb::State::STATE_HANDSHAKE_DONE {
            if let Ok(ssl) = self.get_ssl() {
                debug_assert!(ssl == tun.ssl.as_nonnull());
                if unsafe { openssl3::SSL_get_state(ssl.as_ptr()) }
                    == openssl3::OSSL_HANDSHAKE_STATE_TLS_ST_OK
                {
                    tun.state = pb::State::STATE_HANDSHAKE_DONE;
                }
            }
        }
    }

    /// Reads data from the BIO.
    fn read(&self, buffer: &mut [u8]) -> Result<usize, pb::IOError> {
        let tun = self.get_tunnel().ok_or(pb::IOError::IOERROR_SYSTEM_ERROR)?;
        self.synchronize_states(tun);
        (tun.io).set_state(tun.state);
        (tun.io).read(buffer).map_err(|e| e.into_io_error())
    }

    /// Writes data to the BIO.
    fn write(&self, buffer: &[u8]) -> Result<usize, pb::IOError> {
        let tun = self.get_tunnel().ok_or(pb::IOError::IOERROR_SYSTEM_ERROR)?;
        self.synchronize_states(tun);
        (tun.io).set_state(tun.state);
        (tun.io).write(buffer).map_err(|e| e.into_io_error())
    }

    /// Flushes data.
    fn flush(&self) -> Result<(), pb::IOError> {
        let tun = self.get_tunnel().ok_or(pb::IOError::IOERROR_SYSTEM_ERROR)?;
        (tun.io).flush().map_err(|e| e.into_io_error())
    }
}

/// Reflects an IO error in the BIO flags.
///
/// When an IO interface raises an error, this function sets the appropriate
/// flags to the BIO state depending on the error.
fn bio_reflect_io_error(
    error: pb::IOError,
    on_retry: impl FnOnce() -> c_int,
    on_close: impl FnOnce() -> c_int,
    default_return_value: impl Into<c_int>,
) -> c_int {
    match error {
        pb::IOError::IOERROR_IN_PROGRESS | pb::IOError::IOERROR_WOULD_BLOCK => on_retry(),
        pb::IOError::IOERROR_CLOSED | pb::IOError::IOERROR_REFUSED => on_close(),
        _ => default_return_value.into(),
    }
}

/// BIO write callback.
unsafe extern "C" fn bio_write(
    bio: *mut NativeBio,
    data: *const c_char,
    len: usize,
    written: *mut usize,
) -> c_int {
    let bio = Bio(NonNull::new_unchecked(bio));
    bio.clear_retry_flag();
    match bio.write(std::slice::from_raw_parts(data.cast(), len)) {
        Ok(n) => {
            *written = n;
            1
        }
        Err(e) => bio_reflect_io_error(
            e,
            || {
                bio.set_retry_write_flag();
                -1
            },
            || {
                bio.declare_closed();
                -1
            },
            -1,
        ),
    }
}

/// BIO read callback.
unsafe extern "C" fn bio_read(
    bio: *mut NativeBio,
    data: *mut c_char,
    len: usize,
    written: *mut usize,
) -> c_int {
    let bio = Bio(NonNull::new_unchecked(bio));
    bio.clear_retry_flag();
    match bio.read(std::slice::from_raw_parts_mut(data.cast(), len)) {
        Ok(n) => {
            *written = n;
            1
        }
        Err(e) => bio_reflect_io_error(
            e,
            || {
                bio.set_retry_read_flag();
                -1
            },
            || {
                bio.declare_closed();
                -1
            },
            -1,
        ),
    }
}

/// BIO control callback.
unsafe extern "C" fn bio_ctrl(
    bio: *mut NativeBio,
    cmd: c_int,
    larg: i64,
    _pargs: *mut c_void,
) -> i64 {
    match cmd as u32 {
        openssl3::BIO_CTRL_SET_CLOSE => {
            openssl3::BIO_set_shutdown(bio, larg as i32);
            1
        }
        openssl3::BIO_CTRL_GET_CLOSE => openssl3::BIO_get_shutdown(bio) as i64,
        openssl3::BIO_CTRL_FLUSH => {
            if Bio(NonNull::new_unchecked(bio)).flush().is_err() {
                0
            } else {
                1
            }
        }
        _ => 0,
    }
}

/// BIO create callback (never used).
unsafe extern "C" fn bio_create(_bio: *mut openssl3::bio_st) -> c_int {
    1
}

/// BIO destroy callback (never used).
unsafe extern "C" fn bio_destroy(_bio: *mut NativeBio) -> c_int {
    1
}

/// Static BIO method.
pub(super) const BIO_METH_OBJECT: openssl3::bio_method_st = openssl3::bio_method_st {
    type_: openssl3::BIO_TYPE_SOCKET as i32,
    name: ptr::null_mut(),
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
    brecvmmsg: None,
    bsendmmsg: None,
};

pub(super) const BIO_METHOD: NonNull<openssl3::BIO_METHOD> =
    unsafe { NonNull::new_unchecked((&BIO_METH_OBJECT as *const openssl3::BIO_METHOD).cast_mut()) };

#[cfg(test)]
mod test {
    use super::*;
    use crate::support::Pimpl;

    /// Creates a new BIO.
    fn new_bio(meth: Option<NonNull<openssl3::BIO_METHOD>>) -> Pimpl<'static, NativeBio> {
        unsafe {
            Pimpl::new(
                openssl3::BIO_new(
                    meth.map(|p| p.as_ptr().cast_const())
                        .unwrap_or(openssl3::BIO_s_mem()),
                ),
                |x| openssl3::BIO_free_all(x),
            )
        }
        .unwrap()
    }

    /// Returns a couple of bool that indicates if the read and write flags
    /// are respectively set.
    fn get_read_write_flags(bio: NonNull<NativeBio>) -> (bool, bool) {
        (
            unsafe {
                // `BIO_should_read` is a C macro: `BIO_test_flags(ptr, BIO_FLAGS_READ)`.
                openssl3::BIO_test_flags(bio.as_ptr(), openssl3::BIO_FLAGS_READ as c_int)
            } == openssl3::BIO_FLAGS_READ as c_int,
            unsafe {
                // `BIO_should_write` is a C macro: `BIO_test_flags(ptr, BIO_FLAGS_WRITE)`
                openssl3::BIO_test_flags(bio.as_ptr(), openssl3::BIO_FLAGS_WRITE as c_int)
            } == openssl3::BIO_FLAGS_WRITE as c_int,
        )
    }

    /// Declares a BIO as open (opposite to close).
    fn set_open(bio: NonNull<NativeBio>) {
        unsafe {
            // `BIO_set_close` is a C macro.
            openssl3::BIO_ctrl(
                bio.as_ptr(),
                openssl3::BIO_CTRL_SET_CLOSE as c_int,
                0,
                ptr::null_mut(),
            )
        };
    }

    /// Returns the closed state of a BIO.
    fn get_close_state(bio: NonNull<NativeBio>) -> bool {
        (unsafe {
            // `BIO_get_close` is a C macro.
            openssl3::BIO_ctrl(
                bio.as_ptr(),
                openssl3::BIO_CTRL_GET_CLOSE as c_int,
                0,
                ptr::null_mut(),
            )
        }) == 1
    }

    /// Tests [`Bio::clear_retry_flag`].
    #[test]
    fn test_clear_retry_flag() {
        let bio = new_bio(None);
        let bio_wrapped = Bio(bio.as_nonnull());
        bio_wrapped.set_retry_read_flag();
        bio_wrapped.set_retry_write_flag();
        let flags_before = get_read_write_flags(bio.as_nonnull());
        bio_wrapped.clear_retry_flag();

        let result = get_read_write_flags(bio.as_nonnull());

        assert_eq!((flags_before, result), ((true, true), (false, false)));
    }

    /// Tests [`Bio::set_retry_read_flag`].
    #[test]
    fn test_set_retry_read_flag() {
        let bio = new_bio(None);
        let bio_wrapped = Bio(bio.as_nonnull());
        bio_wrapped.set_retry_read_flag();

        let result = get_read_write_flags(bio.as_nonnull());

        assert_eq!(result, (true, false));
    }

    /// Tests [`Bio::set_retry_read_flag`].
    #[test]
    fn test_set_retry_write_flag() {
        let bio = new_bio(None);
        let bio_wrapped = Bio(bio.as_nonnull());
        bio_wrapped.set_retry_write_flag();

        let result = get_read_write_flags(bio.as_nonnull());

        assert_eq!(result, (false, true));
    }

    /// Tests [`Bio::declare_closed`].
    #[test]
    fn test_declare_closed() {
        let bio = new_bio(None);
        set_open(bio.as_nonnull());
        let close_before = get_close_state(bio.as_nonnull());
        let bio_wrapped = Bio(bio.as_nonnull());
        bio_wrapped.declare_closed();

        let result = get_close_state(bio.as_nonnull());

        assert_eq!((close_before, result), (false, true));
    }
}
