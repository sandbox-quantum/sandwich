load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: May 25 2023
_COMMIT = "e2d2587065eacfe97aaae940dd43cd964b71f5b4"
_SHA256SUM = "22cea7e4870e675d699cc8f16da9a05ae25b58753bf4bf176491d7ab3fed627e"

def open_quantum_safe_boringssl_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.boringssl",
        urls = ["https://github.com/open-quantum-safe/boringssl/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = _SHA256SUM,
        strip_prefix = "boringssl-{commit}".format(commit = _COMMIT),
        patch_args = ["-p1"],
        patches = [
            "//vendor/github.com/open-quantum-safe/boringssl:warning_fixes.patch",
        ],
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
