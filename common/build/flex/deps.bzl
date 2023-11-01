load("@rules_m4//m4:m4.bzl", "m4_register_toolchains")
load("@rules_bison//bison:bison.bzl", "bison_register_toolchains")
load("@rules_flex//flex:flex.bzl", "flex_register_toolchains")

def flex_dependencies():
    m4_register_toolchains(version = "1.4.18")
    bison_register_toolchains(version = "3.3.2")
    flex_register_toolchains(version = "2.6.4")
