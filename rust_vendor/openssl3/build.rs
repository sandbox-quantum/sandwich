// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate bazelisk;
extern crate build_support;
extern crate env_logger;
extern crate log;

/// Targets to build.
const TARGETS: [&str; 3] = [
    "//rust:openssl3_bindgen",
    "//rust:openssl3_bartleby",
    "//rust:openssl3_bindgen__bindgen",
];

/// Foreign C library to link Sandwich against, in Bazel.
const BAZEL_TARGET_LIBRARY: &str = "libopenssl3_bartleby_bartleby.a";

/// New name of the foreign C library to link Sandwich against.
const OUT_LIBRARY: &str = "libsandwichopenssl3.a";

/// Name of the bindgen file produced by Bazel.
const BAZEL_TARGET_BINDGEN: &str = "openssl3_bindgen__bindgen.rs";

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
        "failed to build OpenSSL 3 and its bindgen"
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
        "failed to link OpenSSL 3"
    );
    log::info!("linked {lib}");
}
