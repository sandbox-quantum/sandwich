# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

# to add new dependencies/upgrade existing ones, edit the `packages` dict, then
# run:
#   CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
def rust_deps():
    crates_repository(
        name = "crate_index",
        cargo_lockfile = "@sandwich//common/build/rust:Cargo.lock",
        lockfile = "@sandwich//common/build/rust:Cargo.Bazel.lock",
        annotations = {
            "protobuf-codegen": [crate.annotation(
                gen_binaries = ["protoc-gen-rust"],
            )],
        },
        packages = {
            "byteorder": crate.spec(
                version = "1.4.3",
            ),
            "async-trait": crate.spec(
                version = "0.1.72",
            ),
            "bytes": crate.spec(
                version = "1.4.0",
            ),
            "clap": crate.spec(
                version = "4.1.4",
                features = ["derive"],
            ),
            "env_logger": crate.spec(
                version = "0.10.0",
            ),
            "futures-util": crate.spec(
                version = "0.3.17",
            ),
            "hex-literal": crate.spec(
                version = "0.4.1",
            ),
            "log": crate.spec(
                version = "0.4.17",
                features = ["release_max_level_info"],
            ),
            "opentelemetry": crate.spec(
                version = "0.19.0",
            ),
            "opentelemetry-proto": crate.spec(
                version = "0.3.0",
            ),
            "opentelemetry_api": crate.spec(
                version = "0.19.0",
            ),
            "prost": crate.spec(
                version = "0.12.0",
            ),
            "protobuf": crate.spec(
                version = "3.3.0",
            ),
            "protobuf-codegen": crate.spec(
                version = "3.3.0",
            ),
            "reqwest": crate.spec(
                version = "0.11.18",
                features = ["blocking"],
            ),
            "rand_core": crate.spec(
                version = "0.6.4",
                features = ["getrandom"],
            ),
            "serde": crate.spec(
                version = "1.0.185",
                features = ["derive"],
            ),
            "sha2": crate.spec(
                version = "0.10.7",
            ),
            "shlex": crate.spec(
                version = "1.1.0",
            ),
            "socket2": crate.spec(
                version = "0.5.4",
            ),
            "syn": crate.spec(
                version = "2.0.29",
            ),
            "tempfile": crate.spec(
                version = "3.7.0",
            ),
            "tinytemplate": crate.spec(
                version = "1.2.1",
            ),
            "polling": crate.spec(
                version = "2.8.0",
            ),
        },
    )
