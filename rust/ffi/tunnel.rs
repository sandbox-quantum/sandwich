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

//! Sandwich tunnel module for FFI.

/// A serialized [`pb_api::TunnelVerifier`] for FFI.
#[repr(C)]
pub struct SandwichTunnelVerifierSerialized {
    /// Buffer containing the serialized tunnel verifier message.
    pub(self) src: *const std::ffi::c_void,

    /// Size of the buffer.
    pub(self) n: usize,
}

unsafe impl std::marker::Sync for SandwichTunnelVerifierSerialized {}

/// A `TunnelVerifier` with the `EmptyVerifier` case serialized.
const TUNNEL_VERIFIER_WITH_EMPTY_VERIFIER_SERIALIZED: [u8; 2] = [0x12, 0x00];

/// A static const variable that binds to a `SandwichTunnelVerifierSerialized`
/// with an Empty verifier.
#[no_mangle]
#[used]
pub static SandwichTunnelVerifierEmpty: SandwichTunnelVerifierSerialized =
    SandwichTunnelVerifierSerialized {
        src: TUNNEL_VERIFIER_WITH_EMPTY_VERIFIER_SERIALIZED
            .as_ptr()
            .cast(),
        n: TUNNEL_VERIFIER_WITH_EMPTY_VERIFIER_SERIALIZED.len(),
    };

/// Instantiates a new tunnel from a serialized protobuf configuration message.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_new(
    ctx: *mut std::ffi::c_void,
    cio: *const super::io::Settings,
    verifier_serialized: SandwichTunnelVerifierSerialized,
    tun: *mut *mut std::ffi::c_void,
) -> *mut super::Error {
    let mut b: Box<Box<dyn crate::context::Context>> = unsafe { Box::from_raw(ctx as *mut _) };

    let slice = unsafe {
        std::slice::from_raw_parts(verifier_serialized.src as *const u8, verifier_serialized.n)
    };
    let mut tunnel_verifier = pb_api::TunnelVerifier::new();

    if let Err(e) =
        <_ as protobuf::Message>::merge_from_bytes(&mut tunnel_verifier, slice).map_err(|e| {
            crate::Error::from((
                pb::TunnelError::TUNNELERROR_INVALID,
                format!("invalid serialized verifier: {e}"),
            ))
        })
    {
        return e.into();
    }

    let io: Box<dyn crate::IO> = Box::new(unsafe { *cio });
    let r = b.new_tunnel(io, tunnel_verifier);
    Box::into_raw(b);
    match r {
        Ok(t) => {
            if !tun.is_null() {
                unsafe {
                    *tun = Box::into_raw(Box::new(t)) as *mut std::ffi::c_void;
                }
            }
            std::ptr::null_mut()
        }
        Err((e, _)) => e.into(),
    }
}

/// Releases a tunnel.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_free(tun: *mut std::ffi::c_void) {
    if !tun.is_null() {
        let _: Box<Box<dyn crate::IO>> = unsafe { Box::from_raw(tun as *mut _) };
    }
}

/// Performs the handshake.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_handshake(
    tun: *mut std::ffi::c_void,
    state: *mut std::ffi::c_int,
) -> *mut super::Error {
    use protobuf::Enum;
    let mut b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let r = b.handshake();
    Box::into_raw(b);
    match r {
        Err(e) => {
            unsafe { *state = pb::HandshakeState::HANDSHAKESTATE_ERROR.value() };
            e.into()
        }
        Ok(v) => {
            unsafe { *state = v.value().value() };
            std::ptr::null_mut()
        }
    }
}

/// Performs a read operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_read(
    tun: *mut std::ffi::c_void,
    dst: *mut std::ffi::c_void,
    n: usize,
    r: *mut usize,
) -> i32 {
    use protobuf::Enum;
    let mut b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let res = b.read(unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, n) });
    Box::into_raw(b);
    match res {
        Ok(rn) => unsafe {
            *r = rn;
            pb::RecordError::RECORDERROR_OK
        },
        Err(e) => e.value(),
    }
    .value()
}

/// Performs a write operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_write(
    tun: *mut std::ffi::c_void,
    src: *const std::ffi::c_void,
    n: usize,
    w: *mut usize,
) -> i32 {
    use protobuf::Enum;
    let mut b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let res = b.write(unsafe { std::slice::from_raw_parts(src as *const u8, n) });
    Box::into_raw(b);
    match res {
        Ok(wn) => unsafe {
            *w = wn;
            pb::RecordError::RECORDERROR_OK
        },
        Err(e) => e.value(),
    }
    .value()
}

/// Performs a close operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_close(tun: *mut std::ffi::c_void) {
    let mut b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let _ = b.close();
    Box::into_raw(b);
}

/// Returns the state of the tunnel.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_state(tun: *mut std::ffi::c_void) -> i32 {
    use protobuf::Enum;
    let b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let r = b.state();
    Box::into_raw(b);
    r.value().value()
}

/// Releases the underlying I/O.
/// This method is a no-op, as it is not safe.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_io_release(_tun: *mut std::ffi::c_void) {}
