// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich tunnel module for FFI.

use std::ffi::{c_int, c_void};

use protobuf::Enum;

use crate::ffi::{support, Error};
use crate::tunnel::{self, Context, Tunnel};

use super::IO;

/// A serialized [`pb_api::TunnelConfiguration`] for FFI.
#[repr(C)]
pub struct SandwichTunnelConfigurationSerialized {
    /// Buffer containing the serialized tunnel configuration message.
    src: *const c_void,

    /// Size of the buffer.
    n: usize,
}

unsafe impl Sync for SandwichTunnelConfigurationSerialized {}

/// A `TunnelConfiguration` with the [`pb_api::TunnelVerifier`] set to `EmptyVerifier`.
const TUNNEL_CONFIGURATION_WITH_EMPTY_VERIFIER_SERIALIZED: [u8; 4] = [0x0a, 0x02, 0x12, 0x00];

/// A static const variable that binds to a `SandwichTunnelConfigurationSerialized`
/// with an Empty verifier for the tunnel verifier.
#[no_mangle]
#[used]
pub static SandwichTunnelConfigurationVerifierEmpty: SandwichTunnelConfigurationSerialized =
    SandwichTunnelConfigurationSerialized {
        src: TUNNEL_CONFIGURATION_WITH_EMPTY_VERIFIER_SERIALIZED
            .as_ptr()
            .cast(),
        n: TUNNEL_CONFIGURATION_WITH_EMPTY_VERIFIER_SERIALIZED.len(),
    };

/// Instantiates a new tunnel from a serialized protobuf configuration message.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_new(
    ctx: *mut c_void,
    cio: *const IO,
    configuration_serialized: SandwichTunnelConfigurationSerialized,
    tun: *mut *mut c_void,
) -> *mut Error {
    let b: &mut Context = unsafe { &mut *ctx.cast() };

    let slice = unsafe {
        std::slice::from_raw_parts(
            configuration_serialized.src.cast(),
            configuration_serialized.n,
        )
    };
    let mut tunnel_configuration = pb_api::TunnelConfiguration::new();

    if let Err(e) = <_ as protobuf::Message>::merge_from_bytes(&mut tunnel_configuration, slice)
        .map_err(|e| {
            crate::Error::from((
                pb::TunnelError::TUNNELERROR_INVALID,
                format!("invalid tunnel configuration: {e}"),
            ))
        })
    {
        return e.into();
    }

    let io: Box<dyn tunnel::IO> = Box::new(unsafe { *cio });
    let r = b.new_tunnel(io, tunnel_configuration);
    match r {
        Ok(t) => {
            if !tun.is_null() {
                unsafe {
                    *tun = Box::into_raw(Box::new(t)).cast();
                }
            }
            std::ptr::null_mut()
        }
        Err((e, _)) => e.into(),
    }
}

/// Adds a tracer object to a tunnel object.
#[no_mangle]
#[cfg(feature = "tracer")]
pub extern "C" fn sandwich_tunnel_add_tracer(
    tun: *mut c_void,
    context_cstr: *const std::ffi::c_char,
    fd: c_int,
) {
    use std::fs::File;
    use std::os::fd::FromRawFd;

    use crate::support::tracing::{
        convert_cstring, extract_context, SandwichSpanExporter, SandwichTracer,
    };

    let mut b = unsafe { Box::<Tunnel>::from_raw(tun.cast()) };
    let context_str = convert_cstring(context_cstr);

    let ctx: opentelemetry_api::Context = match context_str {
        Some(c) => extract_context(c),
        None => opentelemetry_api::Context::new(),
    };
    let file_object = unsafe { File::from_raw_fd(fd) };

    let exporter = SandwichSpanExporter::new(file_object);
    let tracer = SandwichTracer::new(ctx, exporter);

    b.add_tracer(tracer);
    Box::into_raw(b);
}

/// Releases a tunnel.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_free(tun: *mut c_void) {
    if !tun.is_null() {
        let _: Box<Tunnel> = unsafe { Box::from_raw(tun.cast()) };
    }
}

/// Performs the handshake.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_handshake(tun: *mut c_void, state: *mut c_int) -> *mut Error {
    let mut b = unsafe { Box::<Tunnel>::from_raw(tun.cast()) };
    let r = b.handshake();
    Box::into_raw(b);
    match r {
        Err(e) => {
            unsafe { *state = pb::HandshakeState::HANDSHAKESTATE_ERROR.value() };
            e.into()
        }
        Ok(v) => {
            unsafe { *state = support::to_c_int(v.value().value()) };
            std::ptr::null_mut()
        }
    }
}

/// Performs a read operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_read(
    tun: *mut c_void,
    dst: *mut c_void,
    n: usize,
    r: *mut usize,
) -> c_int {
    let mut b = unsafe { Box::<Tunnel>::from_raw(tun.cast()) };
    let res = b.read(unsafe { std::slice::from_raw_parts_mut(dst.cast(), n) });
    Box::into_raw(b);
    let ret = match res {
        Ok(rn) => unsafe {
            *r = rn;
            pb::RecordError::RECORDERROR_OK
        },
        Err(e) => e.value(),
    }
    .value();

    support::to_c_int(ret)
}

/// Performs a write operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_write(
    tun: *mut c_void,
    src: *const c_void,
    n: usize,
    w: *mut usize,
) -> c_int {
    let mut b = unsafe { Box::<Tunnel>::from_raw(tun.cast()) };
    let res = b.write(unsafe { std::slice::from_raw_parts(src.cast(), n) });
    Box::into_raw(b);
    let ret = match res {
        Ok(wn) => unsafe {
            *w = wn;
            pb::RecordError::RECORDERROR_OK
        },
        Err(e) => e.value(),
    }
    .value();

    support::to_c_int(ret)
}

/// Performs a close operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_close(tun: *mut c_void) {
    let mut b = unsafe { Box::<Tunnel>::from_raw(tun.cast()) };
    let _ = b.close();
    Box::into_raw(b);
}

/// Returns the state of the tunnel.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_state(tun: *mut c_void) -> c_int {
    let b = unsafe { Box::<Tunnel>::from_raw(tun.cast()) };
    let r = b.state();
    Box::into_raw(b);
    support::to_c_int(r.value().value())
}

/// Releases the underlying I/O.
/// This method is a no-op, as it is not safe.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_io_release(_tun: *mut c_void) {}
