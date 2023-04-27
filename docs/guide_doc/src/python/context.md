# Context

## Description

`Context` is a class assembling configuration and `Sandwich handle` to create `Context` handle

Inputs:
- [`Sandwich`](sandwich.md) handle
- [`Configuration`](configuration.md) either from `client` or `server`

Output:
- `Context` handle


## Usage

```python

from sandwich.proto.api import SandwichAPI
from sandwich import Sandwich, Context

def create_client_context(s: Sandwich) -> Context:
    """Creates the configuration for the client.

    Returns:
        Configuration for the client.
    """
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS
    conf.client.tls.common_options.kem.append("kyber512")

    cert = conf.client.tls.trusted_certificates.add().static
    cert.data.filename = "testdata/cert.pem"
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    return Context(s, conf)


def create_server_context(s: Sandwich) -> Context:
    """"Creates the configuration for the server".
    Returns:

        Configuration for the server.
    """
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.server.tls.common_options.kem.append("kyber512")
    conf.server.tls.certificate.static.data.filename = "testdata/cert.pem"
    conf.server.tls.certificate.static.format = EncodingFormat.ENCODING_FORMAT_PEM

    conf.server.tls.private_key.static.data.filename = "testdata/key.pem"
    conf.server.tls.private_key.static.format = EncodingFormat.ENCODING_FORMAT_PEM

    return Context(s, conf)

if __name__ == "__main__":
    client_ctx = create_client_context(sandwich)

    server_ctx = create_server_context(sandwich)
```
