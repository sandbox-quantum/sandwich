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

/// Target to build.
const TARGETS: [&str; 1] = ["//proto/api/v1:api_rust_proto"];

/// Parent directory's name for the generated Rust file.
const RUST_FILES_PARENT: &str = "sandwich_api_proto.proto.rust";

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
            if build_support::fs::parent_matches(artifact, RUST_FILES_PARENT)
                && build_support::fs::file_matches_extension(artifact, "rs")
            {
                let file_name = cargo_unwrap!(
                    artifact
                        .file_name()
                        .ok_or_else(|| format!("{} has no filename", artifact.to_string_lossy())),
                    "failed to use a compiled protobuf file"
                );
                let out = cargo_unwrap!(
                    build_support::out_dir_path(file_name),
                    "failed to re-export a compiled protobuf file"
                );
                cargo_unwrap!(
                    build_support::protobuf::sanitize(artifact, &out),
                    "failed to sanitize a protobuf file"
                );
            }
            None
        }),
        "failed to build sandwich-api-proto"
    );
}