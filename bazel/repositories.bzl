load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//common/build/flex:repositories.bzl", "flex_repositories")
load("//vendor/github.com/doxygen/doxygen:BUILD.bzl", "doxygen_fetch_archive")
load("//vendor/github.com/open-quantum-safe/liboqs:BUILD.bzl", "liboqs_fetch_archive")
load("//vendor/github.com/open-quantum-safe/openssl:BUILD.bzl", "open_quantum_safe_openssl_no_liboqs_fetch_archive")
load("//vendor/github.com/open-quantum-safe/boringssl:BUILD.bzl", "open_quantum_safe_boringssl_fetch_archive")
load("//vendor/github.com/sandbox-quantum/bartleby:BUILD.bzl", "com_github_sandboxquantum_bartleby_fetch_archive")
load("//vendor/github.com/protocolbuffers/protobuf:BUILD.bzl", "protocolbuffers_protobuf_pull_git_repo")

def sandwich_repositories():
    maybe(
        http_archive,
        name = "rules_pkg",
        sha256 = "8f9ee2dc10c1ae514ee599a8b42ed99fa262b757058f65ad3c384289ff70c4b8",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
            "https://github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "74d544d96f4a5bb630d465ca8bbcfe231e3594e5aae57e1edbf17a6eb3ca2506",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "rules_foreign_cc",
        sha256 = "476303bd0f1b04cc311fc258f1708a5f6ef82d3091e53fd1977fa20383425a6a",
        strip_prefix = "rules_foreign_cc-0.10.1",
        url = "https://github.com/bazelbuild/rules_foreign_cc/archive/refs/tags/0.10.1.tar.gz",
    )

    maybe(
        http_archive,
        name = "rules_python",
        sha256 = "b593d13bb43c94ce94b483c2858e53a9b811f6f10e1e0eedc61073bd90e58d9c",
        strip_prefix = "rules_python-0.12.0",
        url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.12.0.tar.gz",
    )

    maybe(
        http_archive,
        name = "io_bazel_rules_go",
        sha256 = "bfc5ce70b9d1634ae54f4e7b495657a18a04e0d596785f672d35d5f505ab491a",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.40.0/rules_go-v0.40.0.zip",
            "https://github.com/bazelbuild/rules_go/releases/download/v0.40.0/rules_go-v0.40.0.zip",
        ],
    )

    maybe(
        http_archive,
        name = "bazel_gazelle",
        sha256 = "efbbba6ac1a4fd342d5122cbdfdb82aeb2cf2862e35022c752eaddffada7c3f3",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.27.0/bazel-gazelle-v0.27.0.tar.gz",
            "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.27.0/bazel-gazelle-v0.27.0.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "rules_rust",
        sha256 = "6357de5982dd32526e02278221bb8d6aa45717ba9bbacf43686b130aa2c72e1e",
        urls = [
            "https://github.com/bazelbuild/rules_rust/releases/download/0.30.0/rules_rust-v0.30.0.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "com_google_googletest",
        sha256 = "7897bfaa5ad39a479177cfb5c3ce010184dbaee22a7c3727b212282871918751",
        strip_prefix = "googletest-a4ab0abb93620ce26efad9de9296b73b16e88588",
        urls = ["https://github.com/google/googletest/archive/a4ab0abb93620ce26efad9de9296b73b16e88588.tar.gz"],
    )

    ASPECT_BAZEL_LIB_VERSION = "1.34.0"
    maybe(
        http_archive,
        name = "aspect_bazel_lib",
        sha256 = "44f4f6d1ea1fc5a79ed6ca83f875038fee0a0c47db4f9c9beed097e56f8fad03",
        strip_prefix = "bazel-lib-{}".format(ASPECT_BAZEL_LIB_VERSION),
        url = "https://github.com/aspect-build/bazel-lib/releases/download/v{version}/bazel-lib-v{version}.tar.gz".format(version = ASPECT_BAZEL_LIB_VERSION),
    )

    flex_repositories()
    doxygen_fetch_archive()
    liboqs_fetch_archive()
    open_quantum_safe_openssl_no_liboqs_fetch_archive()
    open_quantum_safe_boringssl_fetch_archive()
    com_github_sandboxquantum_bartleby_fetch_archive()
    protocolbuffers_protobuf_pull_git_repo()
