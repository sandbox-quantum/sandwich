load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: Oct 25 2023
_COMMIT = "4dac252a16815b0612e79e63efd5b8aebeacd98a"
_SHA256SUM = "74ccd97da7b9d57e9ec878549a242bbc1bd8a9a6f7ae401260731c51311b177d"

def open_quantum_safe_oqs_provider_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.oqs-provider",
        urls = ["https://github.com/open-quantum-safe/oqs-provider/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = _SHA256SUM,
        patch_args = ["-p1"],
        patches = [
            "@sandwich//vendor/github.com/open-quantum-safe/oqs-provider:include_missing_header.patch",
            "@sandwich//vendor/github.com/open-quantum-safe/oqs-provider:install_in_standard_output.patch",
        ],
        strip_prefix = "oqs-provider-{commit}".format(commit = _COMMIT),
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
