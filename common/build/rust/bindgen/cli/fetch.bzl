load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def common_build_rust_bindgen_cli_fetch_archive():
    maybe(
        http_archive,
        name = "bindgen-cli",
        build_file = "//common/build/rust/bindgen/cli:BUILD.bindgen-cli.bazel",
        sha256 = "33373a4e0ec8b6fa2654e0c941ad16631b0d564cfd20e7e4b3db4c5b28f4a237",
        strip_prefix = "bindgen-cli-0.65.1",
        type = "tar.gz",
        urls = ["https://crates.io/api/v1/crates/bindgen-cli/0.65.1/download"],
    )
