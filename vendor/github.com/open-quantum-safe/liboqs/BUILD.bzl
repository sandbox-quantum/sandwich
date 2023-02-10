load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def liboqs_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.liboqs",
        urls = ["https://github.com/open-quantum-safe/liboqs/archive/a1bdce98949a228269abcd65727d1093706ba13c.tar.gz"],
        sha256 = "951cc782577efd2dd493bee8618dd66faf33219df63ff13fd095d7a37c888140",
        strip_prefix = "liboqs-a1bdce98949a228269abcd65727d1093706ba13c",
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
