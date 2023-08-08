load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

_VERSION = "0.2.2"
_SHA256SUM = "4a3b80e3dfc4040dd68f0b310fa7516758115461eb762ddfae042f3179863575"
_RELEASE_DATE = "Apr 24 2023"

def com_github_sandboxquantum_bartleby_fetch_archive():
    maybe(
        http_archive,
        name = "com_sandboxquantum_bartleby",
        urls = ["https://github.com/sandbox-quantum/bartleby/releases/download/{version}/bartleby-v{version}.tar.gz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
