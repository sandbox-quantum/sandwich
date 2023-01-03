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

//! Root module.
//!
//! Author: thb-sb

pub(crate) mod pimpl;

pub mod context;
pub use context::Context;

pub mod errors;
pub use errors::Error;

pub mod io;
pub use io::IO;

pub mod tunnel;
pub use tunnel::Tunnel;
