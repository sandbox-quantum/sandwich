load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: Aug 17 2023
_VERSION = "0.3.0"
_SHA256SUM = "e38ac4e63400358fa9e322c3ac501acaee6dbd6bec64ce1d97b0519a39dddb64"

def com_github_sandboxquantum_bartleby_fetch_archive():
    maybe(
        http_archive,
        name = "com_sandboxquantum_bartleby",
        urls = ["https://github.com/sandbox-quantum/bartleby/releases/download/{version}/bartleby-v{version}.tar.gz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
    )
