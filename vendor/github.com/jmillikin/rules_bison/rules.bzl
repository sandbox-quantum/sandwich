load("@rules_bison//bison:bison.bzl", "BISON_TOOLCHAIN_TYPE", "bison_toolchain")
load("@rules_m4//m4:m4.bzl", "M4_TOOLCHAIN_TYPE")

def _get_bin_impl(ctx):
    bison = bison_toolchain(ctx)

    return [
        DefaultInfo(
            files = depset([bison.bison_tool.executable]),
            runfiles = ctx.runfiles(files = [bison.bison_tool.executable], transitive_files = bison.all_files),
        ),
    ]

get_bin = rule(
    implementation = _get_bin_impl,
    toolchains = [
        BISON_TOOLCHAIN_TYPE,
        M4_TOOLCHAIN_TYPE,
    ],
)
