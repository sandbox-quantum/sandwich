// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Wrapper for rand_core.

extern crate rand_core;

/// Generates some randmo bytes using `rand_core's OsRng`.
pub fn rand(b: &mut (impl AsMut<[u8]> + ?Sized)) {
    <rand_core::OsRng as rand_core::RngCore>::fill_bytes(&mut rand_core::OsRng, b.as_mut());
}

#[cfg(test)]
mod test {
    use super::rand;

    /// Test rand from a slice.
    #[test]
    fn test_slice() {
        let mut data = [0u8; 42];

        rand(&mut data[..]);
    }

    /// Test rand from a &Vec.
    #[test]
    fn test_vec() {
        let mut data = vec![0u8; 42];

        rand(&mut data);
    }
}
