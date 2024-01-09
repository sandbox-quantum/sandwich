load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: Jan 8 2024
_COMMIT = "c2c969c02889f2766d78a74ffb7d4c3a6dab9cd5"
_SHA256SUM = "eca66246feccdd7e69e5562bacaec8d0880d9a259074ba0cea3775f245612a50"

def liboqs_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.liboqs",
        urls = ["https://github.com/open-quantum-safe/liboqs/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = _SHA256SUM,
        strip_prefix = "liboqs-{commit}".format(commit = _COMMIT),
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
        patches = ["@sandwich//vendor/github.com/open-quantum-safe/liboqs:fix_find_package_Threads.patch"],
        patch_args = ["-p1"],
    )
