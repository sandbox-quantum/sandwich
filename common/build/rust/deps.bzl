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
            "assert_cmd": crate.spec(
                version = "2.0.12",
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
            "hex-literal": crate.spec(
                version = "0.4.1",
            ),
            "log": crate.spec(
                version = "0.4.17",
                features = ["release_max_level_info"],
            ),
            "predicates": crate.spec(
                version = "3.0.3",
            ),
            "protobuf": crate.spec(
                version = "3.2.0",
            ),
            "protobuf-codegen": crate.spec(
                version = "3.2.0",
            ),
            "reqwest": crate.spec(
                version = "0.11.18",
                features = ["blocking"],
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
