load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

def common_build_rust_bindgen_cli_build():
    crates_repository(
        name = "bindgen-cli_deps",
        cargo_lockfile = "@sandwich//common/build/rust/bindgen/cli:Cargo.lock",
        lockfile = "@sandwich//common/build/rust/bindgen/cli:Cargo.Bazel.lock",
        manifests = ["@bindgen-cli//:Cargo.toml"],
    )
