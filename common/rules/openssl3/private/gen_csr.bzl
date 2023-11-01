load("//common/rules/openssl3/private/providers:modules_directory.bzl", "OpenSSLModulesDirectoryProvider")

def _gen_csr_impl(ctx):
    """Implementation for rule `gen_csr`."""

    args = ctx.actions.args()
    args.add("req")
    args.add("-new")
    args.add("-key", ctx.file.private_key)
    args.add("-out", ctx.outputs.out)
    args.add("-outform", ctx.attr.format)
    args.add("-subj", ctx.attr.subject)
    args.add_all(ctx.attr.extensions, before_each = "-addext")

    if ctx.attr.subject_alt_names:
        names = ",".join(ctx.attr.subject_alt_names)
        args.add("-addext", names, format = "subjectAltName=critical,%s")

    conf_file = ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].configuration.file
    env = {
        "OPENSSL_MODULES": ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].path,
        "OPENSSL_CONF": conf_file.path,
    }
    ctx.actions.run(
        outputs = [ctx.outputs.out],
        inputs = depset([conf_file, ctx.file.private_key], transitive = [ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].modules]),
        executable = ctx.executable.openssl_cli,
        arguments = [args],
        env = env,
        mnemonic = "OpenSSLGenCSR",
    )

    return [
        DefaultInfo(),
    ]

"""Generates a CSR using OpenSSL."""
gen_csr = rule(
    doc = "Generates a CSR file using OpenSSL.",
    implementation = _gen_csr_impl,
    attrs = {
        "subject": attr.string(doc = "Certificate subject", mandatory = True),
        "subject_alt_names": attr.string_list(
            doc = "Subject Alternative Names. Values must match the OpenSSL format",
            mandatory = False,
        ),
        "private_key": attr.label(doc = "Private key", allow_single_file = True, mandatory = True),
        "extensions": attr.string_list(doc = "Extensions", mandatory = False),
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
