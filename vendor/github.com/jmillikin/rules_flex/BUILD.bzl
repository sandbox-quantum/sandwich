load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: May 17 2023
_VERSION = "0.2.1"
_SHA256SUM = "8929fedc40909d19a4b42548d0785f796c7677dcef8b5d1600b415e5a4a7749f"

def com_github_jmillikin_rules_flex_fetch_archive():
    maybe(
        http_archive,
        name = "rules_flex",
        urls = ["https://github.com/jmillikin/rules_flex/releases/download/v{version}/rules_flex-v{version}.tar.xz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
    )
