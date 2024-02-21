// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Turbo transport main implementation.
//!
//! This Listener and set of IOs implements Turbo transport based off
//! of the TurboTLS draft.
//! https://datatracker.ietf.org/doc/draft-joseph-tls-turbotls/
//!
//! Note: Proper TCP fallback is not yet implemented.

extern crate log;

pub use io::{Client, Server, TurboListener};

mod io;
mod protocol;
mod rand;
mod support;
