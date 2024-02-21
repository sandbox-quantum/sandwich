// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Asynchronous btree set.

/// Generic set.
pub(crate) struct Set<T>
where
    T: Eq + Ord,
{
    /// The actual set.
    data: std::sync::Mutex<std::collections::BTreeSet<T>>,

    /// The condvar.
    cv: std::sync::Condvar,
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
            cv: std::sync::Condvar::new(),
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
        if self.data.lock().expect("poisoned map mutex").insert(v) {
            self.cv.notify_all();
            Ok(())
        } else {
            Err(std::io::ErrorKind::AlreadyExists.into())
        }
    }

    /// Returns the len of the set.
    fn len(&self) -> usize {
        self.data.lock().expect("poisoned set mutex").len()
    }

    /// Returns the emptiness of the set.
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.data.lock().expect("poisoned set mutex").is_empty()
    }

    /// Check if the set contains a value.
    fn contains<Q>(&self, value: &Q) -> bool
    where
        T: std::borrow::Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.data
            .lock()
            .expect("poisoned set mutex")
            .contains(value)
    }

    /// Waits for a value and execute op on it.
    fn wait_for<Q, Op>(&self, value: &Q, op: Op, dur: Option<std::time::Duration>) -> bool
    where
        T: std::borrow::Borrow<Q> + Ord,
        Q: Ord + ?Sized,
        Op: FnOnce(&T),
    {
        match dur {
            Some(d) => {
                let res = self
                    .cv
                    .wait_timeout_while(
                        self.data
                            .lock()
                            .expect("poisoned set mutex on wait_timeout_while"),
                        d,
                        |data| !data.contains(value),
                    )
                    .expect("poisoned set cv");
                if res.1.timed_out() {
                    false
                } else {
                    op(match res.0.get(value) {
                        Some(v) => v,
                        None => return false,
                    });
                    true
                }
            }
            None => {
                op(
                    match self
                        .cv
                        .wait_while(
                            self.data.lock().expect("poisoned set mutex on wait_while"),
                            |data| !data.contains(value),
                        )
                        .expect("poisoned set cv")
                        .get(value)
                    {
                        Some(v) => v,
                        None => return false,
                    },
                );
                true
            }
        }
    }

    /// Visits the set.
    fn dump<Op>(&self, op: Op, dur: Option<std::time::Duration>) -> bool
    where
        Op: FnOnce(&mut std::collections::BTreeSet<T>),
    {
        op(&mut *match dur {
            Some(d) => {
                let res = self
                    .cv
                    .wait_timeout_while(
                        self.data.lock().expect("poisoned set mutex on dump"),
                        d,
                        |data| data.is_empty(),
                    )
                    .expect("poisoned set cv");
                if res.1.timed_out() {
                    return false;
                }
                res.0
            }
            None => self
                .cv
                .wait_while(
                    self.data.lock().expect("poisoned set mutex on dump"),
                    |data| data.is_empty(),
                )
                .expect("poisoned set cv"),
        });
        true
    }
}

#[cfg(test)]
mod test {
    use super::Set;
    use crate::experimental::turbo::support::BTreeSet;

    /// Tests [`Set`] creation with default.
    #[test]
    fn test_default() {
        let s = Set::<i32>::default();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    /// Tests [`Set::insert`] method.
    #[test]
    fn test_insert_element() {
        let s = Set::<i32>::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        s.insert(42).expect("42 should be insertable");
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);
        s.insert(42).expect_err("42 is already in set");
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);

        s.insert(43).expect("43 should be insertable");
        assert!(!s.is_empty());
        assert_eq!(s.len(), 2);
    }

    /// Tests [`Set::dump`] method.
    #[test]
    fn test_dump() {
        let s = Set::<i32>::default();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);

        s.insert(40).expect("40 should be insertable");
        s.insert(41).expect("41 should be insertable");
        s.insert(42).expect("42 should be insertable");
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());

        let mut values = std::vec::Vec::<i32>::default();
        assert!(s.dump(
            |s| {
                assert_eq!(s.len(), 3);
                assert!(!s.is_empty());
                for v in s.iter() {
                    values.push(*v);
                }
            },
            None
        ));
        assert_eq!(values, vec![40i32, 41i32, 42i32]);
    }

    /// Tests [`Set::dump`] with an empty set first.
    #[test]
    fn test_dump_empty() {
        let s = std::sync::Arc::new(Set::<i32>::default());

        let j = {
            let s = s.clone();
            std::thread::spawn(move || {
                assert!(s.dump(
                    |s| {
                        assert_eq!(s.len(), 1);
                        assert!(s.contains(&42i32));
                        s.clear();
                    },
                    None
                ));
            })
        };

        std::thread::sleep(std::time::Duration::from_millis(200));

        s.insert(42i32).expect("insert should succeed");
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(s.is_empty());
        j.join().expect("join should succeed");
    }

    /// Tests [`Set::dump`] with a timeout.
    #[test]
    fn test_dump_timeout() {
        let s = std::sync::Arc::new(Set::<i32>::default());

        let j = {
            let s = s.clone();
            std::thread::spawn(move || {
                assert!(!s.dump(
                    |s| {
                        assert_eq!(s.len(), 1);
                        assert!(s.contains(&42i32));
                        s.clear();
                    },
                    Some(std::time::Duration::from_millis(500))
                ));
            })
        };

        j.join().expect("join should succeed");

        std::thread::sleep(std::time::Duration::from_millis(100));
        let j = {
            let s = s.clone();
            std::thread::spawn(move || {
                assert!(s.dump(
                    |s| {
                        assert_eq!(s.len(), 1);
                        assert!(s.contains(&42i32));
                        s.clear();
                    },
                    Some(std::time::Duration::from_millis(500))
                ));
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        s.insert(42i32).expect("insert should succeed");
        j.join().expect("join should succeed");
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    /// Tests [`Set::contains`] with a value borrowed by the value type
    /// stored in the set.
    #[test]
    fn test_contain_borrow() {
        #[derive(Eq, PartialEq, Ord, PartialOrd)]
        struct Test(i32);

        impl std::borrow::Borrow<i32> for Test {
            fn borrow(&self) -> &i32 {
                &self.0
            }
        }

        let s = Set::new();
        s.insert(Test(42i32)).expect("failed to insert Test(42i32)");

        assert!(s.contains(&42i32));
        assert!(!s.contains(&41i32));
    }

    /// Tests [`Set::wait_for`] method.
    #[test]
    fn test_wait_for() {
        let s = std::sync::Arc::<Set<i32>>::default();
        let j = {
            let s = s.clone();
            std::thread::spawn(move || assert!(s.wait_for(&42i32, |v| assert_eq!(*v, 42i32), None)))
        };

        s.insert(42i32).expect("failed to insert 42i32");
        j.join().expect("join should succeed");
    }

    /// Tests [`Set::wait_for`] method with first a value that doesn't match the
    /// one seeked by the thread.
    #[test]
    fn test_wait_for_mismatch() {
        let s = std::sync::Arc::<Set<i32>>::default();
        let j = {
            let s = s.clone();
            std::thread::spawn(move || {
                assert!(!s.wait_for(
                    &42i32,
                    |v| assert_eq!(*v, 42i32),
                    Some(std::time::Duration::from_millis(500))
                ))
            })
        };

        std::thread::sleep(std::time::Duration::from_millis(100));
        s.insert(41i32).expect("failed to insert 41i32");
        j.join().expect("join should succeed");

        let j = {
            let s = s.clone();
            std::thread::spawn(move || {
                assert!(s.wait_for(
                    &42i32,
                    |v| assert_eq!(*v, 42i32),
                    Some(std::time::Duration::from_millis(500))
                ))
            })
        };

        std::thread::sleep(std::time::Duration::from_millis(100));
        s.insert(40i32).expect("failed to insert 40i32");
        s.insert(42i32).expect("failed to insert 42i32");
        j.join().expect("join should succeed");
    }
}
