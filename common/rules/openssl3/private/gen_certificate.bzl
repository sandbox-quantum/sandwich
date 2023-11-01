load("//common/rules/openssl3/private/providers:modules_directory.bzl", "OpenSSLModulesDirectoryProvider")

def _gen_certificate_impl(ctx):
    """Implementation for rule `gen_certificate`."""

    cnf = "{}.cnf".format(ctx.executable.openssl_cli.path)

    args = ctx.actions.args()
    args.add("req")
    args.add("-x509", "-new")
    args.add("-key", ctx.file.private_key)
    args.add("-keyform", ctx.attr.private_key_format)
    args.add("-out", ctx.outputs.out)
    args.add("-outform", ctx.attr.format)
    args.add("-nodes")
    args.add("-subj", ctx.attr.subject)
    args.add("-days", "{}".format(ctx.attr.days))
    args.add("-config", cnf)

    if len(ctx.attr.subject_alt_names) > 0:
        names = ",".join(ctx.attr.subject_alt_names)
        args.add("-addext", names, format = "subjectAltName = %s")

    conf_file = ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].configuration.file
    env = {
        "OPENSSL_MODULES": ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].path,
        "OPENSSL_CONF": conf_file.path,
    }

    ctx.actions.run(
        outputs = [ctx.outputs.out],
        inputs = depset([conf_file, ctx.file.private_key], transitive = [ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].modules]),
        env = env,
        executable = ctx.executable.openssl_cli,
        arguments = [args],
        mnemonic = "OpenSSLGenX509",
    )

    return [
        DefaultInfo(),
    ]

"""Generates a certificate using OpenSSL."""
gen_certificate = rule(
    doc = "Generates a certificate using OpenSSL.",
    implementation = _gen_certificate_impl,
    attrs = {
        "out": attr.output(doc = "Output certificate file", mandatory = True),
        "format": attr.string(default = "PEM", doc = "Output format (DER or PEM)", values = ["PEM", "DER"]),
        "private_key": attr.label(doc = "Private key", allow_single_file = True, mandatory = True),
        "private_key_format": attr.string(default = "PEM", doc = "Private key format (DER or PEM)", values = ["PEM", "DER"]),
        "subject": attr.string(default = "/CN=SandboxAQ TEST CA", doc = "Request subject"),
        "days": attr.int(default = 3650, doc = "Number of days the output certificate is valid for"),
        "subject_alt_names": attr.string_list(
            doc = "Subject Alternative Names. Values must match the OpenSSL format",
            mandatory = False,
        ),
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
