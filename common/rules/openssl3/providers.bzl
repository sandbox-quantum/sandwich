load("//common/rules/openssl3/private/providers:provider.bzl", _OpenSSLProvider = "OpenSSLProvider")
load("//common/rules/openssl3/private/providers:providers_configuration.bzl", _OpenSSLProvidersConfigurationProvider = "OpenSSLProvidersConfigurationProvider")

OpenSSLProvider = _OpenSSLProvider
OpenSSLProvidersConfigurationProvider = _OpenSSLProvidersConfigurationProvider
