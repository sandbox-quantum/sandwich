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

pub mod compliance {
    include!(concat!(env!("OUT_DIR"), "/compliance.rs"));
}

pub mod encoding_format {
    include!(concat!(env!("OUT_DIR"), "/encoding_format.rs"));
}

pub mod data_source {
    include!(concat!(env!("OUT_DIR"), "/data_source.rs"));
}

pub mod certificate {
    include!(concat!(env!("OUT_DIR"), "/certificate.rs"));
}

pub mod private_key {
    include!(concat!(env!("OUT_DIR"), "/private_key.rs"));
}

pub mod verifiers {
    include!(concat!(env!("OUT_DIR"), "/verifiers.rs"));
}

pub mod tls {
    include!(concat!(env!("OUT_DIR"), "/tls.rs"));
}

pub mod configuration {
    include!(concat!(env!("OUT_DIR"), "/configuration.rs"));
}

pub use certificate::*;
pub use compliance::*;
pub use configuration::*;
pub use data_source::*;
pub use encoding_format::*;
pub use private_key::*;
pub use tls::*;
pub use verifiers::*;
