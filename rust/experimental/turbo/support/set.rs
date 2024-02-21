// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! BTree set.

/// Alias for BTreeSet.
type Bts<T> = std::collections::BTreeSet<T>;

/// Generic set.
pub(crate) struct Set<T>
where
    T: Eq + Ord,
{
    /// The actual set.
    data: std::cell::UnsafeCell<Bts<T>>,
}

/// Implements [`Default`] for [`Set`].
impl<T> Default for Set<T>
where
    T: Eq + Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Implements [`Set`].
impl<T> Set<T>
where
    T: Eq + Ord,
{
    /// Instantiates a new empty set.
    pub(crate) fn new() -> Self {
        Self {
            data: std::collections::BTreeSet::new().into(),
        }
    }
}

/// Implements [`super::BTreeSet`] for [`Set`].
impl<T> super::BTreeSet<T> for Set<T>
where
    T: Eq + Ord,
{
    /// Inserts an element to the set.
    /// Returns an error if element already exists.
    fn insert(&self, v: T) -> std::io::Result<()> {
        if unsafe { &mut *self.data.get() }.insert(v) {
            Ok(())
        } else {
            Err(std::io::ErrorKind::AlreadyExists.into())
        }
    }

    /// Returns the len of the set.
    fn len(&self) -> usize {
        unsafe { &*self.data.get() }.len()
    }

    /// Returns the emptiness of the set.
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        unsafe { &*self.data.get() }.is_empty()
    }

    /// Check if the set contains a value.
    fn contains<Q>(&self, value: &Q) -> bool
    where
        T: std::borrow::Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        unsafe { &*self.data.get() }.contains(value)
    }

    /// Waits for a value and execute op on it.
    fn wait_for<Q, Op>(&self, value: &Q, op: Op, _dur: Option<std::time::Duration>) -> bool
    where
        T: std::borrow::Borrow<Q> + Ord,
        Q: Ord + ?Sized,
        Op: FnOnce(&T),
    {
        if let Some(value) = unsafe { &*self.data.get() }.get(value) {
            op(value);
            return true;
        }
        false
    }

    /// Visits the set.
    fn dump<Op>(&self, _op: Op, _dur: Option<std::time::Duration>) -> bool
    where
        Op: FnOnce(&mut std::collections::BTreeSet<T>),
    {
        true
    }
}
