// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/// Instantiates a top-level Sandwich context.
#[no_mangle]
pub extern "C" fn sandwich_new() -> *mut crate::Context {
    Box::into_raw(Box::new(crate::Context))
}

/// Frees a top-level Sandwich context.
#[no_mangle]
pub extern "C" fn sandwich_free(ctx: *mut crate::Context) {
    if let Some(ctx) = std::ptr::NonNull::new(ctx) {
        let _ = unsafe { Box::from_raw(ctx.as_ptr()) };
    }
}
