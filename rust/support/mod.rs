// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich support module.

#![allow(unused_imports)]

mod data_source;
mod pimpl;

pub(crate) use data_source::DataSource;
pub(crate) use pimpl::Pimpl;
