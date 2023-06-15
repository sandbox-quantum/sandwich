load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: Jun 11 2023
_COMMIT = "f0e6b8646c5eae0e8052d029079ed3efa498f220"
_SHA256SUM = "1b66d70c9e8eb2a25cef4a43f870f823dc4e84a7a827ec751141347b57482a3c"

def liboqs_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.liboqs",
        urls = ["https://github.com/open-quantum-safe/liboqs/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = _SHA256SUM,
        strip_prefix = "liboqs-{commit}".format(commit = _COMMIT),
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
