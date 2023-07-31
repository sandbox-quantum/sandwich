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

#![allow(ambiguous_glob_reexports)]

extern crate protobuf;

pub mod build {
    include!(concat!(env!("OUT_DIR"), "/bazelisk-proto/build.rs"));
}
pub use build::*;

pub mod analysis_v2 {
    include!(concat!(env!("OUT_DIR"), "/bazelisk-proto/analysis_v2.rs"));
}
pub use analysis_v2::*;
