// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Module support for FFI.

use std::ffi::c_int;

/// Casts a `c_int` to an `i32`.
///
/// This function should be a no-op on all major platforms.
/// Clippy and rustc are issuing warnings when one does `c_int as i32` when
/// `c_int` and `i32` are equivalent. Since we do not want to have warnings, but
/// we also do not want to allow `useless_conversion` warning everywhere we cast
/// `c_int` to an `i32`, having a function to do that cast is the best solution.
#[allow(clippy::useless_conversion)]
pub(crate) fn to_i32(value: c_int) -> i32 {
    value.into()
}

/// Casts a `i32` to a `c_int`.
///
/// This function should be a no-op on all major platforms.
/// See `to_i32` for more information.
#[allow(clippy::useless_conversion)]
pub(crate) fn to_c_int(value: i32) -> c_int {
    value.into()
}
