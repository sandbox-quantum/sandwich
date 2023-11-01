load("//common/rules/openssl3/private/providers:provider.bzl", "OpenSSLProvider")
load("//common/rules/openssl3/private/providers:providers_configuration.bzl", "OpenSSLProvidersConfigurationProvider")

_TEMPLATE = """
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
{providers_list}

{providers_sections}
"""

def _gen_openssl_providers_configuration_impl(ctx):
    """Implementation of rule `gen_openssl_conf_impl`."""

    providers_list = []
    providers_sections = []

    providers = []
    for provider in ctx.attr.providers:
        provider = provider[OpenSSLProvider]
        if provider.name == "default":
            fail("A provider can't be named 'default'")
        providers_list.append("{name} = {name}_sect".format(name = provider.name))
        providers_sections.append("[{name}_sect]\nactivate = {activate}".format(
            name = provider.name,
            activate = "1" if provider.enabled else "0",
        ))
        providers.append(provider)

    providers_list.append("default = default_sect")
    providers_sections.append("[default_sect]\nactivate = {activate}".format(
        activate = "1" if ctx.attr.use_default else "0",
    ))

    conf = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(conf, _TEMPLATE.format(
        providers_list = "\n".join(providers_list),
        providers_sections = "\n\n".join(providers_sections),
    ))

    return [DefaultInfo(
        files = depset([conf]),
    ), OpenSSLProvidersConfigurationProvider(
        file = conf,
        providers = providers,
    )]

gen_openssl_providers_configuration = rule(
    doc = "Generate an OpenSSL configuration for providers",
    implementation = _gen_openssl_providers_configuration_impl,
    attrs = {
        "providers": attr.label_list(
            doc = "OpenSSL providers",
            providers = [OpenSSLProvider],
            mandatory = True,
        ),
        "use_default": attr.bool(
            doc = "Load default OpenSSL provider",
            default = True,
            mandatory = False,
        ),
    },
    provides = [OpenSSLProvidersConfigurationProvider],
)
