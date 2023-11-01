load("//common/rules/openssl3/private/providers:modules_directory.bzl", "OpenSSLModulesDirectoryProvider")

def _sign_csr_impl(ctx):
    """Implementation for rule `sign_csr`."""

    args = ctx.actions.args()
    args.add("x509")
    if ctx.file.ca_certificate:
        args.add("-CA", ctx.file.ca_certificate)
        args.add("-CAkey", ctx.file.ca_private_key)
    else:
        args.add("-key", ctx.file.ca_private_key)
    args.add("-days", "{}".format(ctx.attr.days))
    args.add("-req")
    args.add("-in", ctx.file.csr)
    if ctx.attr.copy_all_extensions:
        args.add("-copy_extensions", "copyall")
    args.add("-out", ctx.outputs.out)
    if ctx.attr.clear_trust:
        args.add("-clrtrust")
    args.add_all(ctx.attr.reject, before_each = "-addreject")
    args.add_all(ctx.attr.trust, before_each = "-addtrust")

    conf_file = ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].configuration.file
    env = {
        "OPENSSL_MODULES": ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].path,
        "OPENSSL_CONF": conf_file.path,
    }
    inputs = [conf_file, ctx.file.ca_private_key, ctx.file.csr]
    if ctx.file.ca_certificate:
        inputs.append(ctx.file.ca_certificate)
    ctx.actions.run(
        outputs = [ctx.outputs.out],
        inputs = depset(inputs, transitive = [ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].modules]),
        executable = ctx.executable.openssl_cli,
        arguments = [args],
        env = env,
        mnemonic = "OpenSSLSignCSR",
    )

    return [
        DefaultInfo(),
    ]

"""Signs a CSR and generates a certificate using OpenSSL."""
sign_csr = rule(
    doc = "Signs a CSR and generates a certificate using OpenSSL.",
    implementation = _sign_csr_impl,
    attrs = {
        "ca_certificate": attr.label(
            doc = "CA certificate. If None, the certificate will be self-signed.",
            allow_single_file = True,
            default = None,
            mandatory = False,
        ),
        "ca_private_key": attr.label(
            doc = "CA private key.",
            allow_single_file = True,
            mandatory = True,
        ),
        "csr": attr.label(
            doc = "CSR file to sign",
            allow_single_file = True,
            mandatory = True,
        ),
        "copy_all_extensions": attr.bool(
            doc = "Copy and sign all extensions from the CSR to the generated certificate",
            default = True,
            mandatory = False,
        ),
        "clear_trust": attr.bool(
            doc = "Clear all trust fields",
            default = True,
            mandatory = False,
        ),
        "reject": attr.string_list(
            doc = "List of explicit rejected purposes for the certificate",
            mandatory = False,
        ),
        "trust": attr.string_list(
            doc = "List of explicit trusted purposes for the certificate",
            mandatory = False,
        ),
        "days": attr.int(default = 3650, doc = "Number of days the output certificate is valid for"),
        "out": attr.output(doc = "Output PEM-encoded certificate file", mandatory = True),
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
