load("//common/rules/openssl3/private/providers:provider.bzl", "OpenSSLProvider")

def _cc_openssl_provider_library_impl(ctx):
    """Implementation of rule `cc_openssl3_provider_library`."""
    libs = []
    for linker_input in ctx.attr.lib[CcInfo].linking_context.linker_inputs.to_list():
        for lib in linker_input.libraries:
            if lib.dynamic_library != None and lib.dynamic_library not in libs:
                libs.append(lib.dynamic_library)
    if len(libs) == 0:
        fail("failed to find a dynamic library in {}".format(ctx.attr.lib))
    if len(libs) > 1:
        fail("more than one dynamic libraries have been found in {}.".format(ctx.attr.lib))

    name = None
    if ctx.attr.override_name != None and len(ctx.attr.override_name) > 0:
        name = ctx.attr.override_name
    else:
        name = libs[0].basename
        ext = libs[0].extension
        name = name[0:len(name) - 1 - len(ext)]

    return [
        OpenSSLProvider(
            module = libs[0],
            enabled = ctx.attr.enabled,
            name = name,
        ),
    ]

"""Declares an OpenSSL 3 provider from a cc library."""
cc_openssl_provider_library = rule(
    doc = "Declares an OpenSSL 3 provider",
    implementation = _cc_openssl_provider_library_impl,
    attrs = {
        "lib": attr.label(
            doc = "CC library",
            providers = [CcInfo],
            mandatory = True,
        ),
        "enabled": attr.bool(
            doc = "Enable this provider",
            default = True,
            mandatory = False,
        ),
        "override_name": attr.string(
            doc = "Override provider's name. Default is the filename",
            mandatory = False,
        ),
    },
    provides = [OpenSSLProvider],
)
