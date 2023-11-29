load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: Nov 23 2023
_VERSION = "3.2.0"
_SHA256SUM = "14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e"

def com_github_openssl_openssl_fetch_archive():
    maybe(
        http_archive,
        name = "com_github_openssl.openssl",
        urls = ["https://github.com/openssl/openssl/releases/download/openssl-{version}/openssl-{version}.tar.gz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
        strip_prefix = "openssl-{version}".format(version = _VERSION),
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
