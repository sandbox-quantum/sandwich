load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

_COMMIT = "1e13c8cb261089fe49120e23b91fc666d562f45b"
_OSSL_VERSION = "1.1.1t"

def open_quantum_safe_openssl_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.openssl",
        urls = ["https://github.com/open-quantum-safe/openssl/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = "57c70de2f7f9c1e266d2a331d6b086b6893d0f127d6e5a201346d8edbe3f1c52",
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
        sha256 = "57c70de2f7f9c1e266d2a331d6b086b6893d0f127d6e5a201346d8edbe3f1c52",
        strip_prefix = "openssl-{commit}".format(commit = _COMMIT),
        patch_args = ["-p1"],
        patches = [
            "//vendor/github.com/open-quantum-safe/openssl:install_no_oqs.patch",
        ],
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
