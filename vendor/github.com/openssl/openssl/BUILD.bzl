load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: Sep 20 2023
_VERSION = "3.1.4"
_SHA256SUM = "840af5366ab9b522bde525826be3ef0fb0af81c6a9ebd84caa600fea1731eee3"

def com_github_openssl_openssl_fetch_archive():
    maybe(
        http_archive,
        name = "com_github_openssl.openssl",
        urls = ["https://github.com/openssl/openssl/releases/download/openssl-{version}/openssl-{version}.tar.gz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
        strip_prefix = "openssl-{version}".format(version = _VERSION),
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
