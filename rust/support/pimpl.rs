// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`Pimpl`] struct.
//!
//! [`Pimpl`] is a convenient and safe wrapper around a raw pointer, with
//! a custom Drop function.

#![allow(dead_code)]

use std::marker::PhantomData;
use std::ptr::NonNull;

/// A deleter.
pub(crate) type Deleter<T> = fn(*mut T);

/// Wrapper around an raw pointer.
pub(crate) struct Pimpl<'a, T> {
    /// The type to own.
    p: NonNull<T>,

    /// The deleter to call on the type.
    del: Option<Deleter<T>>,

    /// A `PhantomData` to explicit the lifetime of the pointer.
    phantom: PhantomData<&'a T>,
}

/// Implements `Send` for [`Pimpl`].
unsafe impl<T> Send for Pimpl<'_, T> {}

/// Implements [`std::fmt::Debug`] for [`Pimpl`].
impl<T> std::fmt::Debug for Pimpl<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pimpl ptr={:?}", self.p)
    }
}

/// Implements [`Pimpl`].
impl<'a, T> Pimpl<'a, T> {
    /// Instantiates a [`Pimpl`] from a raw pointer and optionally a deleter.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let ptr = libc::malloc(42usize);
    ///
    /// // `libc::free` will be called with the pointer when `ptr` gets dropped.
    /// let ptr = unsafe { Pimpl::new(ptr, |p| libc::free(p)) };
    /// ```
    pub fn new(ptr: *mut T, del: Deleter<T>) -> Option<Self> {
        let Some(p) = NonNull::new(ptr) else {
            return None;
        };
        Some(Self {
            p,
            del: Some(del),
            phantom: PhantomData,
        })
    }

    /// Returns a copy of the [`NonNull`] pointer.
    pub(crate) fn as_nonnull(&self) -> NonNull<T> {
        self.p
    }

    /// Returns the raw pointer by consuming the object.
    pub fn into_raw(mut self) -> *mut T {
        self.del = None;
        self.p.as_ptr()
    }
}

/// Implements the custom destructor for [`Pimpl`].
impl<'a, T> Drop for Pimpl<'a, T> {
    fn drop(&mut self) {
        if let Some(del) = self.del {
            (del)(self.p.as_ptr());
        }
    }
}
