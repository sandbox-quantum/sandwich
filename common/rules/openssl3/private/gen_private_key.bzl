load("//common/rules/openssl3/private/providers:modules_directory.bzl", "OpenSSLModulesDirectoryProvider")

def _gen_private_key_impl(ctx):
    """Implementation for rule `gen_private_key`."""

    args = ctx.actions.args()
    args.add("genpkey")
    args.add("-algorithm", ctx.attr.algorithm)
    args.add("-out", ctx.outputs.out)
    args.add("-outform", ctx.attr.format)

    conf_file = ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].configuration.file
    env = {
        "OPENSSL_MODULES": ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].path,
        "OPENSSL_CONF": conf_file.path,
    }
    ctx.actions.run(
        outputs = [ctx.outputs.out],
        inputs = depset([conf_file], transitive = [ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].modules]),
        executable = ctx.executable.openssl_cli,
        arguments = [args],
        env = env,
        mnemonic = "OpenSSLGenPKey",
    )

    return [
        DefaultInfo(),
    ]

"""Generates a private key using OpenSSL."""
gen_private_key = rule(
    doc = "Generates a private key using OpenSSL.",
    implementation = _gen_private_key_impl,
    attrs = {
        "algorithm": attr.string(doc = "Public key algorithm to use", mandatory = True),
        "out": attr.output(doc = "Output private key file", mandatory = True),
        "format": attr.string(default = "PEM", doc = "Output format (DER or PEM)", values = ["PEM", "DER"]),
        "openssl_cli": attr.label(
            cfg = "exec",
            doc = "OpenSSL cli",
            executable = True,
            default = Label("@sandwich//vendor/github.com/openssl/openssl"),
        ),
        "openssl_modules": attr.label(
            doc = "OpenSSL modules",
            default = Label("@sandwich//common/rules/openssl3:modules"),
            providers = [OpenSSLModulesDirectoryProvider],
        ),
    },
)
