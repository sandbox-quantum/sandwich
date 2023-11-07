load("@rules_foreign_cc//foreign_cc:providers.bzl", "ForeignCcDepsInfo")

def _get_bin_impl(ctx):
    exe = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(
        output = exe,
        target_file = ctx.attr._doxygen[OutputGroupInfo].doxygen.to_list()[0],
    )

    return [
        DefaultInfo(
            executable = exe,
        ),
    ]

get_bin = rule(
    implementation = _get_bin_impl,
    executable = True,
    attrs = {
        "_doxygen": attr.label(default = "@com_github_doxygen_doxygen//:doxygen"),
    },
)
