// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate bazelisk;
extern crate build_support;
extern crate env_logger;
extern crate log;

use std::path::{Path, PathBuf};

use bazelisk::Builder;
use build_support::cargo_unwrap;

/// Targets to build.
const TARGETS: [&str; 1] = ["//testdata/..."];

/// Returns the binary path to testdata.
///
/// The binary path to testdata is the path where the produced artifacts that
/// belong to testdata are stored.
///
/// To compute that path, we concatenate the Bazel binary path with the target
/// path to testdata.
fn get_testdata_bin_path(bazel: &bazelisk::Bazelisk) -> PathBuf {
    bazel.bin_path().join("testdata")
}

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let bazelisk = cargo_unwrap!(
        Builder::new().working_dir("../../").unwrap().build(),
        "failed to initialize Bazelisk"
    );

    let testdata_bin_path = get_testdata_bin_path(&bazelisk);

    cargo_unwrap!(
        build_support::bazel::build_targets(&bazelisk, TARGETS, |artifact| {
            let file_name = artifact.file_name().unwrap();
            let out = build_support::out_dir_path(file_name).unwrap();
            if build_support::fs::file_matches_extension(artifact, "pem")
                || build_support::fs::file_matches_extension(artifact, "der")
                || build_support::fs::file_matches_extension(artifact, "key")
            {
                let mut partial_chain: Option<PathBuf> = None;
                for ancestor in artifact.ancestors() {
                    if ancestor == testdata_bin_path.as_path() {
                        break;
                    } else if let Some(partial_chain) = partial_chain.as_mut() {
                        let p = Path::new(ancestor.file_name().unwrap())
                            .join(&partial_chain)
                            .to_path_buf();
                        *partial_chain = p;
                    } else {
                        partial_chain = Some(PathBuf::from(&file_name));
                    }
                }
                partial_chain
                    .map(|p| build_support::out_dir_path(p).unwrap())
                    .or(Some(out))
            } else {
                None
            }
        }),
        "failed to build testdata"
    );
}
