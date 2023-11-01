// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Module containing helpers to create basic IO interface.

use std::io::{Read, Result, Write};

/// Contains the TCP implementation for both [`TcpIo`] and [`crate::io::helpers::tcp::TcpListener`].
pub mod tcp;

impl<RW> crate::IO for RW
where
    RW: Read + Write + Send,
{
    fn read(&mut self, buffer: &mut [u8], _state: pb::State) -> Result<usize> {
        <Self as Read>::read(self, buffer)
    }

    fn write(&mut self, buffer: &[u8], _state: pb::State) -> Result<usize> {
        <Self as Write>::write(self, buffer)
    }
}
