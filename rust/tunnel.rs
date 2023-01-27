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

//! Sandwich tunnel
//!
//! This API provides a wrapper of `saq::sandwich::Tunnel.
//!
//! Author: thb-sb

extern crate sandwich_c;
extern crate sandwich_rust_proto;

use super::context;
use super::errors;
use super::io;
use super::pimpl;

/// `struct SandwichTunnel` wrapper.
type TunnelHandleC = pimpl::Pimpl<sandwich_c::SandwichTunnel>;

/// A record result.
pub type RecordResult = Result<usize, errors::RecordPlaneError>;

/// A Tunnel.
pub struct Tunnel(TunnelHandleC);

impl Tunnel {
    /// Constructs a tunnel from a borrowed context and a borrowed I/O interface.
    pub fn new<Io: io::IO>(
        context: &mut context::Context,
        ioint: &mut Io,
    ) -> Result<Self, errors::Error> {
        let mut iohandle = io::IOHandle::try_from(ioint)?;
        let context_c = context
            .handle_mut()
            .as_raw_mut()
            .ok_or(errors::Error::from(
                sandwich_rust_proto::SystemError::SYSTEMERROR_MEMORY,
            ))?;
        let ioint_c = iohandle
            .handle_mut()
            .as_raw_mut()
            .ok_or(errors::Error::from(
                sandwich_rust_proto::SystemError::SYSTEMERROR_MEMORY,
            ))?;

        let mut handle = std::ptr::null_mut::<::sandwich_c::SandwichTunnel>();
        let err = unsafe { sandwich_c::sandwich_tunnel_new(context_c, ioint_c, &mut handle) };
        if err != std::ptr::null_mut() {
            Err(errors::Error::from(errors::error_handle_c_from_raw(err)))
        } else {
            iohandle.handle_mut().into_raw();
            Ok(Self(TunnelHandleC::from_raw(
                handle,
                Some(|ptr| unsafe { sandwich_c::sandwich_tunnel_free(ptr) }),
            )))
        }
    }

    /// Performs the handshake.
    pub fn handshake(&mut self) -> Result<(), errors::HandshakeState> {
        errors::HandshakeState::from_c_or(
            unsafe { sandwich_c::sandwich_tunnel_handshake(self.0.as_raw_mut().unwrap()) } as i32,
            |_| {},
            (),
        )
    }

    /// Returns the state of the tunnel.
    pub fn state(&mut self) -> errors::State {
        errors::State::from_c(unsafe {
            sandwich_c::sandwich_tunnel_state(self.0.as_raw_mut().unwrap())
        } as i32)
    }

    /// Reads some data from the tunnel.
    pub fn read(&mut self, buf: &mut [u8]) -> RecordResult {
        let mut r = 0u64;
        errors::RecordPlaneError::from_c_or(
            unsafe {
                sandwich_c::sandwich_tunnel_read(
                    self.0.as_raw_mut().unwrap(),
                    std::mem::transmute::<*mut u8, *mut std::ffi::c_void>(buf.as_mut_ptr()),
                    buf.len() as u64,
                    &mut r,
                )
            } as i32,
            |re| -> usize { *re as usize },
            &r,
        )
    }

    /// Write some data to the tunnel.
    pub fn write(&mut self, buf: &[u8]) -> RecordResult {
        let mut r = 0u64;
        errors::RecordPlaneError::from_c_or(
            unsafe {
                sandwich_c::sandwich_tunnel_write(
                    self.0.as_raw_mut().unwrap(),
                    std::mem::transmute::<*const u8, *const std::ffi::c_void>(buf.as_ptr()),
                    buf.len() as u64,
                    &mut r,
                )
            } as i32,
            |re| -> usize { *re as usize },
            &r,
        )
    }

    /// Close the tunnel.
    pub fn close(&mut self) {
        unsafe {
            sandwich_c::sandwich_tunnel_close(self.0.as_raw_mut().unwrap());
        }
    }
}
