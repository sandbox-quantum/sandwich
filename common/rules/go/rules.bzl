load("@io_bazel_rules_go//go:def.bzl", "go_context")
load("@io_bazel_rules_go//go/private:providers.bzl", "GoSource")

def _get_go_sdk_impl(ctx):
    """Implements the `get_go_sdk` rule.

    Outputs:
      The go SDK and go binary files.
    """
    go_ctx = go_context(ctx)

    return [
        DefaultInfo(
            files = depset([go_ctx.sdk.root_file, go_ctx.go]),
        ),
    ]

"""Returns the go SDK and go binary files.

Outputs:
  The go SDK and go binary.
"""
get_go_sdk = rule(
    implementation = _get_go_sdk_impl,
    attrs = {
        "_go_context_data": attr.label(
            default = "@io_bazel_rules_go//:go_context_data",
        ),
    },
    toolchains = ["@io_bazel_rules_go//go:toolchain"],
)
