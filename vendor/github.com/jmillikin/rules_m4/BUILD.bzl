load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: May 15 2023
_VERSION = "0.2.3"
_SHA256SUM = "10ce41f150ccfbfddc9d2394ee680eb984dc8a3dfea613afd013cfb22ea7445c"

def com_github_jmillikin_rules_m4_fetch_archive():
    maybe(
        http_archive,
        name = "rules_m4",
        urls = ["https://github.com/jmillikin/rules_m4/releases/download/v{version}/rules_m4-v{version}.tar.xz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
    )
