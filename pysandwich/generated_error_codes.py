import pysandwich.proto.errors_pb2 as SandwichErrorProto
from pysandwich.error_base import SandwichException


class APIError(SandwichException):
    """APIError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.APIERROR_CONFIGURATION: {
            "msg": """Configuration error.""",
        },
        SandwichErrorProto.APIERROR_SOCKET: {
            "msg": """Socket error.""",
        },
        SandwichErrorProto.APIERROR_TUNNEL: {
            "msg": """Tunnel error.""",
        },
    }


class ConfigurationError(SandwichException):
    """ConfigurationError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.CONFIGURATIONERROR_INVALID_IMPLEMENTATION: {
            "msg": """The selected implementation is invalid.""",
        },
        SandwichErrorProto.CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION: {
            "msg": """The selected implementation isn&#39;t supported.""",
        },
        SandwichErrorProto.CONFIGURATIONERROR_INVALID: {
            "msg": """Invalid configuration.""",
        },
        SandwichErrorProto.CONFIGURATIONERROR_INVALID_LISTENER: {
            "msg": """Invalid Listener configuration.""",
        },
    }


class ProtobufError(SandwichException):
    """ProtobufError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.PROTOBUFERROR_EMPTY: {
            "msg": """The protobuf message is empty.""",
        },
        SandwichErrorProto.PROTOBUFERROR_TOO_BIG: {
            "msg": """The protobuf message is too large.""",
        },
        SandwichErrorProto.PROTOBUFERROR_PARSE_FAILED: {
            "msg": """Failed to parse the protobuf message.""",
        },
        SandwichErrorProto.PROTOBUFERROR_NULLPTR: {
            "msg": """A null pointer was supplied.
 This error is thrown by &#39;sandwich_context_new&#39;, when the given source
 buffer is a null pointer.""",
        },
        SandwichErrorProto.PROTOBUFERROR_INVALID_ARGUMENT: {
            "msg": """/ An invalid value was given.""",
        },
    }


class TLSConfigurationError(SandwichException):
    """TLSConfigurationError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.TLSCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION: {
            "msg": """The selected implementation isn&#39;t supported.""",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_INVALID_CASE: {
            "msg": """The configuration case (client/server) isn&#39;t valid.""",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_EMPTY: {
            "msg": """The configuration is empty.""",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION: {
            "msg": """Unsupported protocol version error.""",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE: {
            "msg": """/ Inconsistency between a private key and the corresponding certificate.""",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_INVALID: {
            "msg": """Invalid configuration.""",
        },
    }


class CertificateError(SandwichException):
    """CertificateError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.CERTIFICATEERROR_MALFORMED: {
            "msg": """Malformed certificate.""",
        },
        SandwichErrorProto.CERTIFICATEERROR_EXPIRED: {
            "msg": """Expired certificate.""",
        },
        SandwichErrorProto.CERTIFICATEERROR_NOT_FOUND: {
            "msg": """Certificate not found.""",
        },
        SandwichErrorProto.CERTIFICATEERROR_UNKNOWN: {
            "msg": """Unknown error. Can wrap a SystemError.""",
        },
        SandwichErrorProto.CERTIFICATEERROR_UNSUPPORTED: {
            "msg": """Certificate not supported by the underlying implementation.""",
        },
    }


class PrivateKeyError(SandwichException):
    """PrivateKeyError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.PRIVATEKEYERROR_MALFORMED: {
            "msg": """Malformed private key.""",
        },
        SandwichErrorProto.PRIVATEKEYERROR_NOT_FOUND: {
            "msg": """Private key not found.""",
        },
        SandwichErrorProto.PRIVATEKEYERROR_UNKNOWN: {
            "msg": """Unknown error. Can wrap a SystemError.""",
        },
        SandwichErrorProto.PRIVATEKEYERROR_UNSUPPORTED: {
            "msg": """Certificate not supported by the underlying implementation.""",
        },
        SandwichErrorProto.PRIVATEKEYERROR_NOT_SERVER: {
            "msg": """Not a server configuration.""",
        },
    }


class ASN1Error(SandwichException):
    """ASN1Error exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.ASN1ERROR_INVALID_FORMAT: {
            "msg": """Invalid format.""",
        },
        SandwichErrorProto.ASN1ERROR_MALFORMED: {
            "msg": """Malformed ASN.1 document.""",
        },
    }


class ALPNError(SandwichException):
    """ALPNError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.ALPNERROR_LENGTH_ERROR: {
            "msg": """Protocol length is longer than 255 bytes.""",
        },
        SandwichErrorProto.ALPNERROR_INVALID_STRING: {
            "msg": """Protocol contains &#39;\x00&#39; byte or invalid string.""",
        },
    }


class DataSourceError(SandwichException):
    """DataSourceError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.DATASOURCEERROR_EMPTY: {
            "msg": """Empty data source.""",
        },
        SandwichErrorProto.DATASOURCEERROR_INVALID_CASE: {
            "msg": """Invalid case for data source.""",
        },
        SandwichErrorProto.DATASOURCEERROR_NOT_FOUND: {
            "msg": """Data not found on local filesystem.""",
        },
    }


class KEMError(SandwichException):
    """KEMError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.KEMERROR_INVALID: {
            "msg": """Invalid or unsupported KEM.""",
        },
        SandwichErrorProto.KEMERROR_TOO_MANY: {
            "msg": """Too many KEMs.""",
        },
    }


class SystemError(SandwichException):
    """SystemError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.SYSTEMERROR_MEMORY: {
            "msg": """Memory error (e.g. allocation failed).""",
        },
        SandwichErrorProto.SYSTEMERROR_INTEGER_OVERFLOW: {
            "msg": """Integer overflow.""",
        },
    }


class SocketError(SandwichException):
    """SocketError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.SOCKETERROR_BAD_FD: {
            "msg": """Bad file descriptor.""",
        },
        SandwichErrorProto.SOCKETERROR_CREATION_FAILED: {
            "msg": """Socket creation failed.""",
        },
        SandwichErrorProto.SOCKETERROR_BAD_NETADDR: {
            "msg": """Invalid network address.""",
        },
        SandwichErrorProto.SOCKETERROR_NETADDR_UNKNOWN: {
            "msg": """Failed to resolve network address.""",
        },
        SandwichErrorProto.SOCKETERROR_FSTAT_FAILED: {
            "msg": """Syscall &#39;fstat&#39; failed.""",
        },
        SandwichErrorProto.SOCKETERROR_NOT_SOCK: {
            "msg": """File descriptor is not a socket.""",
        },
        SandwichErrorProto.SOCKETERROR_GETSOCKNAME_FAILED: {
            "msg": """Syscall getsockname failed.""",
        },
        SandwichErrorProto.SOCKETERROR_SETSOCKOPT_FAILED: {
            "msg": """Syscall setsockopt failed.""",
        },
        SandwichErrorProto.SOCKETERROR_INVALID_AI_FAMILY: {
            "msg": """Invalid AI family.""",
        },
    }


class HandshakeError(SandwichException):
    """HandshakeError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.HANDSHAKEERROR_INVALID_SERVER_NAME: {
            "msg": """Invalid Server Name.""",
        },
        SandwichErrorProto.HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED: {
            "msg": """Certficate verification failed.""",
        },
        SandwichErrorProto.HANDSHAKEERROR_CERTIFICATE_EXPIRED: {
            "msg": """Certificate has expired.""",
        },
        SandwichErrorProto.HANDSHAKEERROR_CERTIFICATE_REVOKED: {
            "msg": """Certificate was revoked.""",
        },
        SandwichErrorProto.HANDSHAKEERROR_INVALID_CERTIFICATE: {
            "msg": """Invalid Certificate.""",
        },
        SandwichErrorProto.HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED: {
            "msg": """Signature verification error.""",
        },
        SandwichErrorProto.HANDSHAKEERROR_UNKNOWN_ERROR: {
            "msg": """Unknown handshake error.""",
        },
    }


class TunnelError(SandwichException):
    """TunnelError exception."""

    _ERRORS_MAP = {
        SandwichErrorProto.TUNNELERROR_INVALID: {
            "msg": """Invalid tunnel configuration.""",
        },
        SandwichErrorProto.TUNNELERROR_VERIFIER: {
            "msg": """Invalid tunnel verifier.""",
        },
        SandwichErrorProto.TUNNELERROR_UNKNOWN: {
            "msg": """Unknown error.""",
        },
    }


_ERROR_KIND_MAP = {
    SandwichErrorProto.ERRORKIND_API: APIError,
    SandwichErrorProto.ERRORKIND_CONFIGURATION: ConfigurationError,
    SandwichErrorProto.ERRORKIND_PROTOBUF: ProtobufError,
    SandwichErrorProto.ERRORKIND_TLS_CONFIGURATION: TLSConfigurationError,
    SandwichErrorProto.ERRORKIND_CERTIFICATE: CertificateError,
    SandwichErrorProto.ERRORKIND_PRIVATE_KEY: PrivateKeyError,
    SandwichErrorProto.ERRORKIND_ASN1: ASN1Error,
    SandwichErrorProto.ERRORKIND_ALPN: ALPNError,
    SandwichErrorProto.ERRORKIND_DATA_SOURCE: DataSourceError,
    SandwichErrorProto.ERRORKIND_KEM: KEMError,
    SandwichErrorProto.ERRORKIND_SYSTEM: SystemError,
    SandwichErrorProto.ERRORKIND_SOCKET: SocketError,
    SandwichErrorProto.ERRORKIND_HANDSHAKE: HandshakeError,
    SandwichErrorProto.ERRORKIND_TUNNEL: TunnelError,
}
