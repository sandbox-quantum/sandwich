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

/// A deleter.
pub(crate) type Deleter<T> = fn(*mut T);

/// Wrapper around an raw pointer.
#[derive(Debug)]
pub(crate) struct Pimpl<'ptr, T> {
    /// The type to own.
    obj: *mut T,

    /// The deleter to call on the type.
    del: Option<Deleter<T>>,

    /// A `PhantomData` to explicit the lifetime of the pointer.
    phantom: std::marker::PhantomData<&'ptr T>,
}

/// Instantiates a [`Pimpl`] from a raw pointer to `T`.
impl<'ptr, T> From<*mut T> for Pimpl<'ptr, T> {
    fn from(obj: *mut T) -> Self {
        Self {
            obj,
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
