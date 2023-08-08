load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

_COMMIT = "70d83cacc85b0c45331c16bcb9acf6a233e895e3"
_SHA256SUM = "f13d9e0ee6d39a9085dcff7b478ea352d12f67aab437fd42206cd84737f3d9a5"
_OSSL_VERSION = "1.1.1u"

def open_quantum_safe_openssl_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.openssl",
        urls = ["https://github.com/open-quantum-safe/openssl/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = _SHA256SUM,
        strip_prefix = "openssl-{commit}".format(commit = _COMMIT),
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
        urls = ["https://github.com/open-quantum-safe/openssl/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = _SHA256SUM,
        strip_prefix = "openssl-{commit}".format(commit = _COMMIT),
        patch_args = ["-p1"],
        patches = [
            "//vendor/github.com/open-quantum-safe/openssl:install_no_oqs.patch",
        ],
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
