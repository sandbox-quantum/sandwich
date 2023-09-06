load("//common/build/rust/bindgen:repositories.bzl", "rust_bindgen_repositories")
load("//common/build/rust/bindgen:rules.bzl", "rust_bindgen_register_toolchains")
load("//common/build/rust/proto:toolchains.bzl", "common_build_rust_proto_register_toolchains")
load("//common/build/rust:deps.bzl", "rust_deps")
load("@aspect_bazel_lib//lib:repositories.bzl", "aspect_bazel_lib_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
load("@com_sandboxquantum_bartleby//bartleby:repositories.bzl", "bartleby_repositories")
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
load("@rules_python//python:repositories.bzl", "python_register_toolchains")
load("@rules_rust//bindgen:repositories.bzl", "rust_bindgen_dependencies")
load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")
load("@rules_rust//proto/protobuf:repositories.bzl", "rust_proto_protobuf_dependencies")
load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

def sandwich_deps():
    rules_foreign_cc_dependencies()

    aspect_bazel_lib_dependencies()

    python_register_toolchains(
        name = "python3",
        python_version = "3.10",
    )

    protobuf_deps()

    go_repository(
        name = "org_golang_google_protobuf",
        importpath = "google.golang.org/protobuf",
        sum = "h1:d0NfwRgPtno5B1Wa6L2DAG+KivqkdutMf1UhdNx175w=",
        version = "v1.28.1",
    )

    go_rules_dependencies()

    go_register_toolchains(version = "1.18.4")

    # See https://github.com/bazelbuild/bazel-gazelle/issues/678
    gazelle_dependencies(go_repository_default_config = "@//:WORKSPACE.bazel")

    rules_rust_dependencies()

    rust_register_toolchains(
        edition = "2021",
        extra_target_triples = [
            "aarch64-apple-darwin",
            "aarch64-apple-ios",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux",
        ],
    )

    crate_universe_dependencies()

    rust_deps()

    rust_bindgen_dependencies()

    rust_bindgen_repositories()

    rust_bindgen_register_toolchains()

    common_build_rust_proto_register_toolchains()

    rust_proto_protobuf_dependencies()

    bartleby_repositories()
