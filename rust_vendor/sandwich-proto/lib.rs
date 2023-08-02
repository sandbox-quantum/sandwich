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

#![allow(box_pointers)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]
#![allow(deprecated)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unknown_lints)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_results)]
#![allow(improper_ctypes)]
#![allow(ambiguous_glob_reexports)]

extern crate protobuf;

pub mod errors {
    include!(concat!(env!("OUT_DIR"), "/errors.rs"));
}

pub mod io {
    include!(concat!(env!("OUT_DIR"), "/io.rs"));
}

pub mod tunnel {
    include!(concat!(env!("OUT_DIR"), "/tunnel.rs"));
}

pub mod sandwich {
    include!(concat!(env!("OUT_DIR"), "/sandwich.rs"));
}

pub use errors::*;
pub use io::*;
pub use sandwich::*;
pub use tunnel::*;
