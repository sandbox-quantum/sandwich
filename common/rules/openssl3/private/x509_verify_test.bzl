load("@bazel_skylib//lib:shell.bzl", "shell")
load("//common/rules/openssl3/private/providers:modules_directory.bzl", "OpenSSLModulesDirectoryProvider")

"""Script to run when the x509 verify is expected to succeed."""
_SUCCESS_SCRIPT_TEMPLATE = """#!/bin/sh
{args}
"""

"""Script to run when the x509 verify is expected to fail."""
_FAIL_SCRIPT_TEMPLATE = """#!/bin/sh
if {args}; then
  echo "x509 verify process should have failed."
  exit 1
fi
"""

"""Script to run when the x509 verify is expected to fail with a given error string."""
_FAIL_WITH_ERRSTR_SCRIPT_TEMPLATE = """#!/bin/sh
ERRFILE=$(mktemp)
if {args} >"$ERRFILE" 2>&1; then
  echo "x509 verify process should have failed."
  rm $ERRFILE
  exit 1
fi
cat $ERRFILE
if ! grep -q "{errstr}" "$ERRFILE"; then
  printf "x509 verify failed but '%s' was not found" "{errstr}"
  echo "stderr:"
  cat $ERRFILE
  rm $ERRFILE
  exit 1
fi
rm $ERRFILE
"""

def _x509_verify_test_impl(ctx):
    """Implementation for rule `x509_verify_test`."""

    args = []
    args.append(shell.quote(ctx.executable.openssl_cli.short_path))
    args.append("verify")

    inputs = []

    if ctx.file.ca_certificate:
        args += ["-CAfile", shell.quote(ctx.file.ca_certificate.short_path)]
        inputs.append(ctx.file.ca_certificate)
    if ctx.attr.check_ca_self_signatures:
        args.append("-check_ss_sig")
    args.append("-trusted_first")
    if ctx.attr.verify_depth != 0:
        args += ["-verify_depth", "{}".format(ctx.attr.verify_depth)]
    if ctx.attr.partial_chain:
        args.append("-partial_chain")
    if ctx.attr.x509_strict:
        args.append("-x509_strict")
    for purpose in ctx.attr.purposes:
        args += ["-purpose", shell.quote(purpose)]
    for hostname in ctx.attr.hostnames:
        args += ["-verify_hostname", shell.quote(hostname)]
    if ctx.attr.email:
        args += ["-verify_email", shell.quote(ctx.attr.email)]
    if ctx.attr.ip_address:
        args += ["-verify_ip", shell.quote(ctx.attr.ip_address)]

    for target in ctx.attr.intermediate_certificates:
        for f in target.files.to_list():
            args += ["-untrusted", shell.quote(f.short_path)]
            inputs.append(f)

    args.append(shell.quote(ctx.file.leaf_certificate.short_path))
    inputs.append(ctx.file.leaf_certificate)

    conf_file = ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].configuration.file
    env = {
        "OPENSSL_MODULES": ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].path.replace(ctx.bin_dir.path + "/", ""),
        "OPENSSL_CONF": conf_file.short_path,
    }
    inputs.append(conf_file)
    inputs.append(ctx.executable.openssl_cli)

    script_content = None
    args_joined = " ".join(args)
    if ctx.attr.expect_error:
        if ctx.attr.expect_error_string:
            script_content = _FAIL_WITH_ERRSTR_SCRIPT_TEMPLATE.format(args = args_joined, errstr = ctx.attr.expect_error_string)
        else:
            script_content = _FAIL_SCRIPT_TEMPLATE.format(args = args_joined)
    else:
        if ctx.attr.expect_error_string:
            fail("`expect_error_string` was set but `expect_error` was not.")
        script_content = _SUCCESS_SCRIPT_TEMPLATE.format(args = args_joined)

    script = ctx.actions.declare_file("{}.sh".format(ctx.label.name))
    ctx.actions.write(script, script_content, is_executable = True)

    return [
        DefaultInfo(
            executable = script,
            runfiles = ctx.runfiles(
                files = [],
                transitive_files = depset(inputs, transitive = [ctx.attr.openssl_modules[OpenSSLModulesDirectoryProvider].modules]),
            ),
        ),
        RunEnvironmentInfo(
            environment = env,
        ),
    ]

x509_verify_test = rule(
    doc = "Verifies certificates properties",
    implementation = _x509_verify_test_impl,
    test = True,
    executable = True,
    attrs = {
        "ca_certificate": attr.label(
            doc = "CA certificate",
            allow_single_file = True,
            mandatory = False,
        ),
        "check_ca_self_signatures": attr.bool(
            doc = "Check self signatures for CA certificates",
            default = True,
            mandatory = False,
        ),
        "verify_depth": attr.int(
            doc = "Verify chain depth limit",
            mandatory = False,
        ),
        "partial_chain": attr.bool(
            doc = "Accept partial chains",
            default = False,
            mandatory = False,
        ),
        "x509_strict": attr.bool(
            doc = "Disable certificate compatibility work-arounds",
            default = True,
            mandatory = False,
        ),
        "purposes": attr.string_list(
            doc = "Certificate chain purpose to test. Valid values are: {}".format(", ".join(["sslclient", "sslserver", "nssslserver", "smimesign", "smimeencrypt", "crlsign", "any", "ocshelper", "timestampsign", "codesign"])),
            mandatory = False,
        ),
        "hostnames": attr.string_list(
            doc = "Expected peer hostnames",
            mandatory = False,
        ),
        "email": attr.string(
            doc = "Expected peer email address",
            mandatory = False,
        ),
        "ip_address": attr.string(
            doc = "Expected peer IP address",
            mandatory = False,
        ),
        "intermediate_certificates": attr.label_list(
            doc = "Intermediate certificates",
            allow_files = True,
            mandatory = False,
        ),
        "leaf_certificate": attr.label(
            doc = "Leaf certificate",
            allow_single_file = True,
            mandatory = True,
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
        "expect_error": attr.bool(
            doc = "Turn the test into a failure test",
            default = False,
            mandatory = False,
        ),
        "expect_error_string": attr.string(
            doc = "The expected error string in case of failure",
            mandatory = False,
        ),
    },
)
