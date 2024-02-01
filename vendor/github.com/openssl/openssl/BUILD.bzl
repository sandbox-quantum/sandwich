load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: Jan 30 2024
_VERSION = "3.2.1"
_SHA256SUM = "83c7329fe52c850677d75e5d0b0ca245309b97e8ecbcfdc1dfdc4ab9fac35b39"

def com_github_openssl_openssl_fetch_archive():
    maybe(
        http_archive,
        name = "com_github_openssl.openssl",
        urls = ["https://github.com/openssl/openssl/releases/download/openssl-{version}/openssl-{version}.tar.gz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
        strip_prefix = "openssl-{version}".format(version = _VERSION),
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
