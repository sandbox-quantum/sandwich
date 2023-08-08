load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

_WORKSPACE_FILE_CONTENT = """
workspace(name = "{name}")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_cc",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.6/rules_cc-0.0.6.tar.gz"],
    sha256 = "3d9e271e2876ba42e114c9b9bc51454e379cbf0ec9ef9d40e2ae4cec61a31b40",
    strip_prefix = "rules_cc-0.0.6",
)
"""

def _fetch_llvm_clang_archive(name, url, prefix, sha256sum):
    """Fetches an archive given its URL, its prefix and its SHA-256 digest."""
    maybe(
        http_archive,
        name = name,
        urls = [url],
        strip_prefix = prefix,
        sha256 = sha256sum,
        build_file = Label("//common/build/rust/bindgen:clang.BUILD.bazel"),
        workspace_file_content = _WORKSPACE_FILE_CONTENT.format(
            name = name,
        ),
    )

def _fetch_llvm_release(name, version, platform_string, sha256sum):
    """Fetches an LLVM release based on its version and a platform.

    The version is the version as defined by LLVM. For example: `15.0.0`,
    `16.0.7`.

    The platform string corresponds to the name of the architecture and the os.
    For example: `x86_64-apple-darwin`."""

    prefix = "clang+llvm-{version}-{platform_string}".format(
        version = version,
        platform_string = platform_string,
    )
    file = "{prefix}.tar.xz".format(
        prefix = prefix,
    )
    url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-{version}/{file}".format(
        version = version,
        file = file,
    )
    _fetch_llvm_clang_archive(name, url, prefix, sha256sum)

def rust_bindgen_repositories():
    """Fetches the various LLVM releases for the most common architectures."""

    _fetch_llvm_release(
        name = "bindgen_clang_linux_aarch64",
        version = "15.0.6",
        platform_string = "aarch64-linux-gnu",
        sha256sum = "8ca4d68cf103da8331ca3f35fe23d940c1b78fb7f0d4763c1c059e352f5d1bec",
    )

    _fetch_llvm_release(
        name = "bindgen_clang_linux_x86_64",
        version = "15.0.6",
        platform_string = "x86_64-linux-gnu-ubuntu-18.04",
        sha256sum = "38bc7f5563642e73e69ac5626724e206d6d539fbef653541b34cae0ba9c3f036",
    )

    _fetch_llvm_release(
        name = "bindgen_clang_macos_aarch64",
        version = "16.0.4",
        platform_string = "arm64-apple-darwin22.0",
        sha256sum = "429b8061d620108fee636313df55a0602ea0d14458c6d3873989e6b130a074bd",
    )

    _fetch_llvm_release(
        name = "bindgen_clang_macos_x86_64",
        version = "15.0.7",
        platform_string = "x86_64-apple-darwin21.0",
        sha256sum = "d16b6d536364c5bec6583d12dd7e6cf841b9f508c4430d9ee886726bd9983f1c",
    )

def rust_bindgen_get_component(os, arch, component):
    """Returns the label to a given clang component based on the OS and the architecture."""
    workspace = "@bindgen_clang_{os}_{arch}".format(
        os = os,
        arch = arch,
    )

    return "{workspace}//:{component}".format(
        workspace = workspace,
        component = component,
    )
