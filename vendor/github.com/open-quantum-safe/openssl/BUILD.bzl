load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def open_quantum_safe_openssl_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.openssl",
        urls = ["https://github.com/open-quantum-safe/openssl/archive/e9160975eeb9796ff3550e8c2c35db63157a409b.zip"],
        sha256 = "0b5dc6497a26a672f4596f55419d78ac049f8f2ec46ebbd47382d10a7ba28725",
        strip_prefix = "openssl-e9160975eeb9796ff3550e8c2c35db63157a409b",
        patch_args = ["-p1"],
        patches = [
            "//vendor/github.com/open-quantum-safe/openssl:001-inject-oqsdir.patch",
        ],
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )

def open_quantum_safe_openssl_no_liboqs_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.openssl_no_liboqs",
        urls = ["https://github.com/open-quantum-safe/openssl/archive/e9160975eeb9796ff3550e8c2c35db63157a409b.zip"],
        sha256 = "0b5dc6497a26a672f4596f55419d78ac049f8f2ec46ebbd47382d10a7ba28725",
        strip_prefix = "openssl-e9160975eeb9796ff3550e8c2c35db63157a409b",
        patch_args = ["-p1"],
        patches = [
            "//vendor/github.com/open-quantum-safe/openssl:install_no_oqs.patch",
        ],
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
