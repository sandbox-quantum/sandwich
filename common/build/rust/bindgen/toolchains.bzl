load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

_CLANG_LLVM_BUILD_FILE = """
load("@rules_cc//cc:defs.bzl", "cc_import")

package(default_visibility = ["//visibility:public"])

sh_binary(
    name = "clang",
    srcs = ["bin/clang"],
)

cc_import(
    name = "libclang",
    shared_library = "lib/libclang.{libext}",
)

cc_import(
    name = "libc++",
    shared_library = "lib/libc++.{libext}"
)
"""

def common_build_rust_bindgen_fetch_toolchains():
    maybe(
        http_archive,
        name = "bindgen_clang_osx_arm64",
        urls = ["https://github.com/llvm/llvm-project/releases/download/llvmorg-15.0.7/clang+llvm-15.0.7-arm64-apple-darwin22.0.tar.xz"],
        strip_prefix = "clang+llvm-15.0.7-arm64-apple-darwin22.0",
        sha256 = "867c6afd41158c132ef05a8f1ddaecf476a26b91c85def8e124414f9a9ba188d",
        build_file_content = _CLANG_LLVM_BUILD_FILE.format(libext = "dylib"),
    )

def common_build_rust_bindgen_register_toolchains():
    for t in ("macos_aarch64", "ios_aarch64", "macos_x86_64", "linux_x86_64"):
        native.register_toolchains("//common/build/rust/bindgen:bindgen_toolchain_{}".format(t))
