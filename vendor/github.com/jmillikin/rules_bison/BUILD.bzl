load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

# Release date: May 18 2023
_VERSION = "0.2.2"
_SHA256SUM = "2279183430e438b2dc77cacd7b1dbb63438971b2411406570f1ddd920b7c9145"

def com_github_jmillikin_rules_bison_fetch_archive():
    maybe(
        http_archive,
        name = "rules_bison",
        urls = ["https://github.com/jmillikin/rules_bison/releases/download/v{version}/rules_bison-v{version}.tar.xz".format(version = _VERSION)],
        sha256 = _SHA256SUM,
    )
