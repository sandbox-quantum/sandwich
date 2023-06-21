load("@rules_foreign_cc//foreign_cc:providers.bzl", "ForeignCcDepsInfo")

def _get_bin_impl(ctx):
    deps = ctx.attr.doxygen_cmake[ForeignCcDepsInfo]

    artifacts = ctx.attr.doxygen_cmake[ForeignCcDepsInfo].artifacts.to_list()
    if len(artifacts) == 0:
        fail("foreign_cc rule did not output an artifact")
    art = artifacts[0]

    binfile = ctx.actions.declare_file("doxygen")
    binpath = "{}/{}/doxygen".format(art.gen_dir.path, art.bin_dir_name)

    args = ctx.actions.args()
    args.add(binpath)
    args.add(binfile)
    ctx.actions.run(
        inputs = [art.gen_dir],
        outputs = [binfile],
        executable = "cp",
        arguments = [args],
    )

    return [
        DefaultInfo(
            files = depset([binfile]),
        ),
    ]

get_bin = rule(
    implementation = _get_bin_impl,
    attrs = {
        "doxygen_cmake": attr.label(doc = "Doxygen CMake target", mandatory = True),
    },
)
