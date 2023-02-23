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

//! Defines [`Pimpl`] struct.
//!
//! [`Pimpl`] is a convenient and safe wrapper around a raw pointer, with
//! a custom Drop function.
//!
//! Author: thb-sb

/// A deleter.
pub(crate) type Deleter<T> = fn(*mut T);

/// Wrapper around an raw pointer.
pub(crate) struct Pimpl<'ptr, T> {
    /// The type to own.
    obj: Box<T>,

    /// The deleter to call on the type.
    del: Option<Deleter<T>>,

    /// A `PhantomData` to explicit the lifetime of the pointer.
    phantom: std::marker::PhantomData<&'ptr T>,
}

/// Instantiates a [`Pimpl`] from a owned [`std::boxed::Box`].
impl<'ptr, T> From<Box<T>> for Pimpl<'ptr, T> {
    fn from(obj: Box<T>) -> Self {
        Self {
            obj,
            del: None,
            phantom: std::marker::PhantomData,
        }
    }
}

/// Instantiates a [`Pimpl`] from a raw pointer to `T`.
impl<'ptr, T> From<*mut T> for Pimpl<'ptr, T> {
    fn from(ptr: *mut T) -> Self {
        Self {
            obj: unsafe { Box::from_raw(ptr) },
            del: None,
            phantom: std::marker::PhantomData,
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
        &*self.obj
    }

    /// Returns raw pointer as mutable, or None if pointer is null.
    pub fn as_mut_ptr(&mut self) -> *mut T {
        &mut *self.obj
    }
}

/// Implements the custom destructor for [`Pimpl`].
impl<'ptr, T> Drop for Pimpl<'ptr, T> {
    fn drop(&mut self) {
        let ptr = &mut *self.obj;
        if let Some(del) = self.del {
            (del)(ptr);
        }
    }
}
