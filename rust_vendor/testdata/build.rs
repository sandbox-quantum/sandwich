// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate bazelisk;
extern crate build_support;
extern crate env_logger;
extern crate log;

/// Targets to build.
const TARGETS: [&str; 1] = ["//testdata/..."];

fn main() {
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

    cargo_unwrap!(
        build_support::bazel::build_targets(&bazelisk, TARGETS, |artifact| {
            let file_name = artifact.file_name().unwrap();
            let out = build_support::out_dir_path(file_name).unwrap();
            if build_support::fs::file_matches_extension(artifact, "pem")
                || build_support::fs::file_matches_extension(artifact, "der")
            {
                Some(out)
            } else {
                None
            }
        }),
        "failed to build testdata"
    );
}
