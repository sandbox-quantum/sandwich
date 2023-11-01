load("//common/rules/openssl3/private/providers:providers_configuration.bzl", "OpenSSLProvidersConfigurationProvider")
load("//common/rules/openssl3/private/providers:modules_directory.bzl", "OpenSSLModulesDirectoryProvider")

def _gen_openssl_modules_directory_impl(ctx):
    """Implementation of rule `gen_openssl_modules_directory`."""
    providers = ctx.attr.configuration[OpenSSLProvidersConfigurationProvider].providers

    modules = []
    for provider in providers:
        filename = "{name}.{ext}".format(
            name = provider.name,
            ext = provider.module.extension,
        )
        module = ctx.actions.declare_file("{basedir}/{filename}".format(
            basedir = ctx.label.name,
            filename = filename,
        ))
        ctx.actions.symlink(
            output = module,
            target_file = provider.module,
        )
        modules.append(module)

    modules = depset(modules)
    return [
        DefaultInfo(files = modules),
        OpenSSLModulesDirectoryProvider(
            modules = modules,
            configuration = ctx.attr.configuration[OpenSSLProvidersConfigurationProvider],
            path = "{bin_dir}/{package}/{basedir}".format(
                bin_dir = ctx.bin_dir.path,
                package = ctx.label.package,
                basedir = ctx.label.name,
            ),
        ),
    ]

gen_openssl_modules_directory = rule(
    doc = "Generate a directory that contains all OpenSSL provider modules specified in a given configuration",
    implementation = _gen_openssl_modules_directory_impl,
    attrs = {
        "configuration": attr.label(
            doc = "Configuration",
            providers = [OpenSSLProvidersConfigurationProvider],
            mandatory = True,
        ),
    },
    provides = [OpenSSLModulesDirectoryProvider],
)
