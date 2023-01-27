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

//! Sandwich Context.
//!
//! This API provides a wrapper of `saq::sandwich::Context`.
//!
//! Author: thb-sb

extern crate api_rust_proto as api;
extern crate protobuf;
extern crate sandwich_c;
extern crate sandwich_rust_proto;

use super::errors;
use super::pimpl;

/// `struct SandwichContext` wrapper.
type ContextHandleC = pimpl::Pimpl<sandwich_c::SandwichContext>;

/// A Sandwich context.
pub struct Context(ContextHandleC);

/// Implements a constructor from a borrowed protobuf configuration.
impl TryFrom<&api::Configuration> for Context {
    type Error = errors::Error;

    /// Constructs a ContextHandle from a borrowed protobuf configuration.
    fn try_from(configuration: &api::Configuration) -> Result<Self, Self::Error> {
        let data = <api::Configuration as protobuf::Message>::write_to_bytes(configuration)
            .or_else(|_| {
                Err(Self::Error::from(
                    sandwich_rust_proto::ProtobufError::PROTOBUFERROR_PARSE_FAILED,
                ))
            })?;
        let mut handle = std::ptr::null_mut::<::sandwich_c::SandwichContext>();

        let err = unsafe {
            sandwich_c::sandwich_context_new(
                std::mem::transmute::<*const u8, *const std::ffi::c_void>(data.as_ptr()),
                data.len() as u64,
                &mut handle,
            )
        };
        if err != std::ptr::null_mut() {
            Err(Self::Error::from(errors::error_handle_c_from_raw(err)))
        } else {
            Ok(Self(ContextHandleC::from_raw(
                handle,
                Some(|ptr| unsafe {
                    sandwich_c::sandwich_context_free(ptr);
                }),
            )))
        }
    }
}

/// Implements a constructor from a owned protobuf configuration.
impl TryFrom<api::Configuration> for Context {
    type Error = errors::Error;

    /// Constructs a ContextHandle from a owned protobuf configuration.
    fn try_from(configuration: api::Configuration) -> Result<Self, Self::Error> {
        Self::try_from(&configuration)
    }
}

impl Context {
    /// Borrows the C handle.
    #[allow(dead_code)]
    pub(crate) fn handle(&self) -> &ContextHandleC {
        &self.0
    }

    /// Borrows the C handle.
    pub(crate) fn handle_mut(&mut self) -> &mut ContextHandleC {
        &mut self.0
    }
}
