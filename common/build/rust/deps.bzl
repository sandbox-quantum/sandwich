load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

# to add new dependencies/upgrade existing ones, edit the `packages` dict, then
# run:
#   CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
def rust_deps():
    crates_repository(
        name = "crate_index",
        cargo_lockfile = "//common/build/rust:Cargo.lock",
        lockfile = "//common/build/rust:Cargo.Bazel.lock",
        annotations = {
            "protobuf-codegen": [crate.annotation(
                gen_binaries = ["protoc-gen-rust"],
            )],
        },
        packages = {
            "protobuf": crate.spec(
                version = "3.2.0",
            ),
            "protobuf-codegen": crate.spec(
                version = "3.2.0",
            ),
        },
    )