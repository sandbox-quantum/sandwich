// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(box_pointers)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]
#![allow(deprecated)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unknown_lints)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_results)]
#![allow(improper_ctypes)]
#![allow(ambiguous_glob_reexports)]

extern crate protobuf;


pub mod tracing {
    include!(concat!(env!("OUT_DIR"), "/tracing.rs"));
}

pub use tracing::*;
