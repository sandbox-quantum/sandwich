// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Underlying implementations supported by Sandwich.

#[cfg(any(feature = "openssl1_1_1", feature = "boringssl"))]
#[macro_use]
pub(crate) mod ossl;
