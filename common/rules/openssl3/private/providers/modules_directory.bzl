OpenSSLModulesDirectoryProvider = provider(
    doc = "A directory containing OpenSSL providers (OPENSSL_MODULES)",
    fields = {
        "modules": "depset[File]: modules",
        "configuration": "OpenSSLProvidersConfigurationProvider: configuration",
        "path": "str: Path to the directory",
    },
)
