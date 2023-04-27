load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def com_github_mdbook_fetch_archive():
    _VERSION = "0.4.22"

    # TODO(ducnguyen-sb):
    # An attempt to up this version to 0.4.23 -> 0.4.28 are failed due to unknown configuration
    # that cause `mio` missing when build.
    # In my standalone Bazel build set up, version 0.4.28 works fine
    _SHA256 = "3eb21d6cdd0f01e4dbcc6591aabcb9c210a330119cc917f9a4e92a713d9a32c4"
    maybe(
        http_archive,
        name = "com_github_rust_lang_mdbook",
        build_file = "//vendor/github.com/mdbook:BUILD.mdbook.bazel",
        sha256 = _SHA256,
        urls = [
            "https://github.com/rust-lang/mdBook/archive/refs/tags/v{version}.zip".format(version = _VERSION),
        ],
        strip_prefix = "mdBook-{version}".format(version = _VERSION),
        type = "zip",
    )
