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

extern crate bazelisk;
extern crate build_support;
extern crate env_logger;
extern crate log;

/// Targets to build.
const TARGETS: [&str; 3] = [
    "//rust:openssl1_1_1_bindgen",
    "//rust:openssl1_1_1_bartleby",
    "//rust:openssl1_1_1_bindgen__bindgen",
];

/// Foreign C library to link Sandwich against, in Bazel.
const BAZEL_TARGET_LIBRARY: &str = "libopenssl1_1_1_bartleby_bartleby.a";

/// New name of the foreign C library to link Sandwich against.
const OUT_LIBRARY: &str = "libsandwichopenssl1_1_1.a";

/// Name of the bindgen file produced by Bazel.
const BAZEL_TARGET_BINDGEN: &str = "openssl1_1_1_bindgen__bindgen.rs";

fn main() {
    use build_support::cargo::report_error;
    use build_support::cargo_unwrap;

    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let bazelisk = cargo_unwrap!(
        bazelisk::Builder::new()
            .working_dir("../../")
            .unwrap()
            .build(),
        "failed to initialize Bazelisk"
    );

    let library = cargo_unwrap!(
        build_support::out_dir_path(OUT_LIBRARY),
        "cannot construct library"
    );

    let bindgen_rs = cargo_unwrap!(
        build_support::out_dir_path("lib.rs"),
        "cannot construct `lib.rs`"
    );

    cargo_unwrap!(
        build_support::bazel::build_targets(&bazelisk, TARGETS, |artifact| {
            if build_support::fs::file_name_matches(artifact, BAZEL_TARGET_LIBRARY) {
                Some(library.clone())
            } else if build_support::fs::file_name_matches(artifact, BAZEL_TARGET_BINDGEN) {
                Some(bindgen_rs.clone())
            } else {
                None
            }
        }),
        "failed to build OpenSSL 1.1.1 and its bindgen"
    );

    if !library.is_file() {
        report_error(format!(
            "file {} was not produced",
            library.to_string_lossy()
        ));
    }
    if !bindgen_rs.is_file() {
        report_error(format!(
            "file {} was not produced",
            bindgen_rs.to_string_lossy()
        ));
    }

    let lib = cargo_unwrap!(
        build_support::cargo::link_against(&library),
        "failed to link OpenSSL 1.1.1"
    );
    log::info!("linked {lib}");
}
