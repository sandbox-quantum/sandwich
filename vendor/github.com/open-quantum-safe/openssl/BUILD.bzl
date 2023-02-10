load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def open_quantum_safe_openssl_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.openssl",
        urls = ["https://github.com/open-quantum-safe/openssl/archive/511f387437e7de2c21b23cebecb4ede6b7a99f40.tar.gz"],
        sha256 = "5d74d7fa84b06273481c1d250c20be58578f99992812219eebcbe0349d808121",
        strip_prefix = "openssl-511f387437e7de2c21b23cebecb4ede6b7a99f40",
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
        urls = ["https://github.com/open-quantum-safe/openssl/archive/511f387437e7de2c21b23cebecb4ede6b7a99f40.tar.gz"],
        sha256 = "5d74d7fa84b06273481c1d250c20be58578f99992812219eebcbe0349d808121",
        strip_prefix = "openssl-511f387437e7de2c21b23cebecb4ede6b7a99f40",
        patch_args = ["-p1"],
        patches = [
            "//vendor/github.com/open-quantum-safe/openssl:install_no_oqs.patch",
        ],
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
