load("//vendor/github.com/doxygen/doxygen:BUILD.bzl", "com_github_doxygen_doxygen_fetch_archive")
load("//vendor/github.com/jmillikin/rules_bison:BUILD.bzl", "com_github_jmillikin_rules_bison_fetch_archive")
load("//vendor/github.com/jmillikin/rules_flex:BUILD.bzl", "com_github_jmillikin_rules_flex_fetch_archive")
load("//vendor/github.com/jmillikin/rules_m4:BUILD.bzl", "com_github_jmillikin_rules_m4_fetch_archive")

def mkdocs_repositories():
    com_github_doxygen_doxygen_fetch_archive()
    com_github_jmillikin_rules_bison_fetch_archive()
    com_github_jmillikin_rules_flex_fetch_archive()
    com_github_jmillikin_rules_m4_fetch_archive()
