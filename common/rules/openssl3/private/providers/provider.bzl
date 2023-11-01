OpenSSLProvider = provider(
    doc = "A provider that indicates an OpenSSL provider",
    fields = {
        "module": "File: provider as a module (.so, .dylib)",
        "enabled": "bool: enable this provider",
        "name": "str: Provider's name, as it appears in OpenSSL configuration",
    },
)
