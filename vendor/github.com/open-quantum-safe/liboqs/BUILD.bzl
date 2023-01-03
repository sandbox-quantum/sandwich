load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def liboqs_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.liboqs",
        urls = ["https://github.com/open-quantum-safe/liboqs/archive/ea44f391fd8f43dad6d42026e5c631f82e561a5a.zip"],
        sha256 = "7c7cb1ddde8673c13eb9d3de27a23c21e69bce0ec0652388d402e5707caa746f",
        strip_prefix = "liboqs-ea44f391fd8f43dad6d42026e5c631f82e561a5a",
        patch_args = ["-p1"],
        patches = [
            "//vendor/github.com/open-quantum-safe/liboqs:wno-strict-prototypes.patch",
        ],
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
