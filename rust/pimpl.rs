// Copyright 2022 SandboxAQ
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

//! C PIMPL wrapper for Rust.
//!
//! Author: thb-sb

/// A deleter.
pub(crate) type Deleter<T> = fn(*mut T);

/// Wrapper around an opaque type.
pub(crate) struct Pimpl<T> {
    obj: Option<Box<T>>,
    del: Option<Deleter<T>>,
}

/// Constructs a Pimpl<T> from a owned Box<T>.
impl<T> From<Box<T>> for Pimpl<T> {
    fn from(obj: Box<T>) -> Self {
        Self {
            obj: Some(obj),
            del: None,
        }
    }
}

/// Constructs a Pimpl<T> from a raw pointer to T.
impl<T> From<*mut T> for Pimpl<T> {
    fn from(ptr: *mut T) -> Self {
        Self {
            obj: Some(unsafe { Box::from_raw(ptr) }),
            del: None,
        }
    }
}

impl<T> Pimpl<T> {
    /// Constructs a Pimpl from a raw pointer and a deleter.
    pub fn from_raw(ptr: *mut T, del: Option<Deleter<T>>) -> Self {
        let mut p = <Self as From<*mut T>>::from(ptr);
        p.del = del;
        p
    }

    /// Constructs a Pimpl from a box and a deleter.
    #[allow(dead_code)]
    pub fn from_box(obj: Box<T>, del: Option<Deleter<T>>) -> Self {
        let mut p = <Self as From<Box<T>>>::from(obj);
        p.del = del;
        p
    }

    /// Returns the C pointer.
    #[allow(dead_code)]
    pub fn as_raw(&self) -> Option<*const T> {
        match &self.obj {
            Some(obj) => {
                let ptr: *const T = &**obj;
                if ptr != std::ptr::null() {
                    Some(ptr)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Returns the mutable C pointer.
    pub fn as_raw_mut(&mut self) -> Option<*mut T> {
        match &mut self.obj {
            Some(obj) => {
                let ptr: *mut T = &mut **obj;
                if ptr != std::ptr::null_mut() {
                    Some(ptr)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Take back the ownership of the object.
    #[allow(dead_code)]
    pub fn into_box(&mut self) -> Option<Box<T>> {
        self.obj.take()
    }

    /// Take back the ownership of object, as raw.
    pub fn into_raw(&mut self) -> Option<*mut T> {
        self.obj.take().map(|b| -> *mut T { Box::into_raw(b) })
    }
}

/// Implements the custom destructor for Pimpl<T>.
impl<T> Drop for Pimpl<T> {
    fn drop(&mut self) {
        match self.obj.take() {
            Some(b) => match self.del {
                Some(del) => (del)(Box::into_raw(b)),
                _ => {}
            },
            _ => {}
        }
    }
}
