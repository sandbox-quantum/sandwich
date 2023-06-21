load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: May 18 2023
_VERSION = "1_9_7"
_SHA256SUM = "691777992a7240ed1f822a5c2ff2c4273b57c1cf9fc143553d87f91a0c5970ee"

def com_github_doxygen_doxygen_fetch_archive():
    maybe(
        http_archive,
        name = "doxygen.doxygen",
        urls = ["https://github.com/doxygen/doxygen/archive/refs/tags/Release_{version}.tar.gz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
        patch_args = ["-p1"],
        patches = ["//vendor/github.com/doxygen/doxygen:disable_tests.patch"],
        patch_cmds = ["rm -r testing/"],
        strip_prefix = "doxygen-Release_{version}".format(version = _VERSION),
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
