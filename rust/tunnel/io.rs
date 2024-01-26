// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! This module provides the definition of I/O interfaces specific to the
//! tunnel API.
//!
//! I/O interfaces for tunnels are regular I/O interfaces with the addition
//! of the `set_state` method which allows the I/O interfaces to know the state
//! of the tunnel it is attached to.

/// An IO interface specific to tunnels.
pub trait IO: crate::IO {
    /// Indicates the current state of the tunnel.
    ///
    /// It is guaranteed that the state of the tunnel will not change between
    /// two calls to this callback.
    fn set_state(&mut self, _state: pb::State) {}
}

impl<'a> std::fmt::Debug for dyn IO + 'a {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Box(tunnel::IO)")
    }
}
