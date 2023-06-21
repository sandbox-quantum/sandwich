load("@rules_m4//m4:m4.bzl", "M4_TOOLCHAIN_TYPE", "m4_toolchain")

def _get_bin_impl(ctx):
    m4 = m4_toolchain(ctx)

    return [
        DefaultInfo(
            files = depset([m4.m4_tool.executable]),
            runfiles = ctx.runfiles(files = [m4.m4_tool.executable], transitive_files = m4.all_files),
        ),
    ]

get_bin = rule(
    implementation = _get_bin_impl,
    toolchains = [M4_TOOLCHAIN_TYPE],
)
