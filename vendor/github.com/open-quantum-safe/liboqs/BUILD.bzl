load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

_COMMIT = "d5be452ec8824775da55f16bcb14e54e61ce9ff6"
_DATE = "Apr 28 2023"

def liboqs_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.liboqs",
        urls = ["https://github.com/open-quantum-safe/liboqs/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = "90f1d54f231eddd2f7a089f3ad3f755f8f9510c8440777845df7984fb38849f7",
        strip_prefix = "liboqs-{commit}".format(commit = _COMMIT),
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
