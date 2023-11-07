load("@rules_bison//bison:bison.bzl", "BISON_TOOLCHAIN_TYPE", "bison_toolchain")
load("@rules_m4//m4:m4.bzl", "M4_TOOLCHAIN_TYPE")

def _get_bin_impl(ctx):
    bison = bison_toolchain(ctx)
    exe = ctx.actions.declare_file(ctx.label.name)

    ctx.actions.symlink(
        output = exe,
        target_file = bison.bison_tool.executable,
        is_executable = True,
    )

    return [
        DefaultInfo(
            executable = exe,
            files = depset(
                direct = [bison.bison_tool.executable],
            ),
            runfiles = ctx.runfiles(transitive_files = bison.all_files),
        ),
    ]

get_bin = rule(
    implementation = _get_bin_impl,
    executable = True,
    toolchains = [
        BISON_TOOLCHAIN_TYPE,
        M4_TOOLCHAIN_TYPE,
    ],
)
