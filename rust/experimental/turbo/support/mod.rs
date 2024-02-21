//! Support module.
//!
//! The support module offers various containers and helpers used by
//! Turbo transport.

/// A BTree set.
pub(crate) trait BTreeSet<T>
where
    T: Eq + Ord,
{
    /// Inserts an element to the set.
    /// Returns an error if element already exists.
    fn insert(&self, v: T) -> std::io::Result<()>;

    /// Returns the len of the set.
    fn len(&self) -> usize;

    /// Returns the emptiness of the set.
    fn is_empty(&self) -> bool;

    /// Checks if the set contains a value.
    fn contains<Q>(&self, value: &Q) -> bool
    where
        T: std::borrow::Borrow<Q> + Ord,
        Q: Ord + ?Sized;

    /// Waits for a value and execute op on it.
    fn wait_for<Q, Op>(&self, value: &Q, op: Op, dur: Option<std::time::Duration>) -> bool
    where
        T: std::borrow::Borrow<Q> + Ord,
        Q: Ord + ?Sized,
        Op: FnOnce(&T);

    /// Visits the set.
    fn dump<Op>(&self, op: Op, dur: Option<std::time::Duration>) -> bool
    where
        Op: FnOnce(&mut std::collections::BTreeSet<T>);
}

mod aset;
mod set;
pub(crate) use aset::Set as ASet;
pub(crate) use set::Set;
