load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: Jul 4 2023
_COMMIT = "1ca41b49e9198f510991fb4f350b4a5fd4c1d5ff"
_SHA256SUM = "a16e5fac8623c1ca3508c143f959a39f1d0b830a7b56ec91c0b0fd70644bd2b8"

def open_quantum_safe_boringssl_fetch_archive():
    maybe(
        http_archive,
        name = "open-quantum-safe.boringssl",
        urls = ["https://github.com/open-quantum-safe/boringssl/archive/{commit}.tar.gz".format(commit = _COMMIT)],
        sha256 = _SHA256SUM,
        strip_prefix = "boringssl-{commit}".format(commit = _COMMIT),
        patch_args = ["-p1"],
        patches = [
            "@sandwich//vendor/github.com/open-quantum-safe/boringssl:warning_fixes.patch",
        ],
        build_file_content = """filegroup(name = "all_srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    )
