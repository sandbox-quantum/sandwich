// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`Pimpl`] struct.
//!
//! [`Pimpl`] is a convenient and safe wrapper around a raw pointer, with
//! a custom Drop function.

#![allow(dead_code)]

use std::marker::PhantomData;

/// A deleter.
pub(crate) type Deleter<T> = fn(*mut T);

/// Wrapper around an raw pointer.
pub(crate) struct Pimpl<'ptr, T> {
    /// The type to own.
    obj: *mut T,

    /// The deleter to call on the type.
    del: Option<Deleter<T>>,

    /// A `PhantomData` to explicit the lifetime of the pointer.
    phantom: PhantomData<&'ptr T>,
}

/// Implements `Send` for [`Pimpl`].
unsafe impl<T> Send for Pimpl<'_, T> {}

/// Implements [`std::fmt::Debug`] for [`Pimpl`].
impl<T> std::fmt::Debug for Pimpl<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pimpl ptr={:?}", self.obj)
    }
}

/// Instantiates a [`Pimpl`] from a raw pointer to `T`.
impl<'ptr, T> From<*mut T> for Pimpl<'ptr, T> {
    fn from(obj: *mut T) -> Self {
        Self {
            obj,
            del: None,
            phantom: PhantomData,
        }
    }
}

/// Implements [`Pimpl`].
impl<'ptr, T> Pimpl<'ptr, T> {
    /// Instantiates a [`Pimpl`] from a raw pointer and optionally a deleter.
    ///
    /// # Example
    ///
    /// ```
    /// let ptr = libc::malloc(42usize);
    ///
    /// // `libc::free` will be called with the pointer when `ptr` gets dropped.
    /// let ptr = Pimpl::from_raw(ptr, Some(|p| {libc::free(p);}));
    /// ```
    pub fn from_raw(ptr: *mut T, del: Option<Deleter<T>>) -> Self {
        let mut p = <Self as From<*mut T>>::from(ptr);
        p.del = del;
        p
    }

    /// Returns the raw pointer, or None if pointer is null.
    pub(crate) fn as_ptr(&self) -> *const T {
        self.obj
    }

    /// Returns raw pointer as mutable, or None if pointer is null.
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.obj
    }

    /// Returns the raw pointer by consuming the object.
    pub fn into_raw(mut self) -> *mut T {
        self.del = None;
        let tmp = self.obj;
        self.obj = std::ptr::null_mut();
        tmp
    }
}

/// Implements the custom destructor for [`Pimpl`].
impl<'ptr, T> Drop for Pimpl<'ptr, T> {
    fn drop(&mut self) {
        if let Some(del) = self.del {
            (del)(self.obj);
        }
    }
}

#[cfg(test)]
mod test {
    use super::Pimpl;

    /// Tests `Pimpl` using a pointer from the stack.
    #[test]
    fn test_from_stack() {
        let mut a: i32 = 0;

        let pimpl = Pimpl::from_raw(&mut a as *mut _, None);
        drop(pimpl);
    }
}
