load("@rules_flex//flex:flex.bzl", "FLEX_TOOLCHAIN_TYPE", "flex_toolchain")
load("@rules_m4//m4:m4.bzl", "M4_TOOLCHAIN_TYPE")

def _get_bin_impl(ctx):
    flex = flex_toolchain(ctx)

    return [
        DefaultInfo(
            files = depset([flex.flex_tool.executable]),
            runfiles = ctx.runfiles(files = [flex.flex_tool.executable], transitive_files = flex.all_files),
        ),
    ]

get_bin = rule(
    implementation = _get_bin_impl,
    toolchains = [
        FLEX_TOOLCHAIN_TYPE,
        M4_TOOLCHAIN_TYPE,
    ],
)
