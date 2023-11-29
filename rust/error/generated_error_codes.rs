GenProtoBasedErrorCode!({
      kind: ERRORKIND_API,
      sym: APIError,
      desc: "API errors.
 The following errors can occur during a call to the Context API.",
      values: [
        APIERROR_CONFIGURATION => "Configuration error.",
APIERROR_SOCKET => "Socket error.",
APIERROR_TUNNEL => "Tunnel error.",

      ],
  },
{
      kind: ERRORKIND_CONFIGURATION,
      sym: ConfigurationError,
      desc: "Errors regarding configurations.",
      values: [
        CONFIGURATIONERROR_INVALID_IMPLEMENTATION => "The selected implementation is invalid.",
CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION => "The selected implementation isn&#39;t supported.",
CONFIGURATIONERROR_INVALID => "Invalid configuration.",
CONFIGURATIONERROR_INVALID_LISTENER => "Invalid Listener configuration.",

      ],
  },
{
      kind: ERRORKIND_PROTOBUF,
      sym: ProtobufError,
      desc: "Errors regarding protobuf.",
      values: [
        PROTOBUFERROR_EMPTY => "The protobuf message is empty.",
PROTOBUFERROR_TOO_BIG => "The protobuf message is too large.",
PROTOBUFERROR_PARSE_FAILED => "Failed to parse the protobuf message.",
PROTOBUFERROR_NULLPTR => "A null pointer was supplied.
 This error is thrown by &#39;sandwich_context_new&#39;, when the given source
 buffer is a null pointer.",
PROTOBUFERROR_INVALID_ARGUMENT => "/ An invalid value was given.",

      ],
  },
{
      kind: ERRORKIND_TLS_CONFIGURATION,
      sym: TLSConfigurationError,
      desc: "Errors regarding TLS configurations.",
      values: [
        TLSCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION => "The selected implementation isn&#39;t supported.",
TLSCONFIGURATIONERROR_INVALID_CASE => "The configuration case (client/server) isn&#39;t valid.",
TLSCONFIGURATIONERROR_EMPTY => "The configuration is empty.",
TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION => "Unsupported protocol version error.",
TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE => "Inconsistency between a private key and the corresponding certificate.",
TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE => "Unsupported TLS ciphersuite error.",
TLSCONFIGURATIONERROR_UNSUPPORTED_CONTROL_CHARACTERS => "Control characters are not allowed.",
TLSCONFIGURATIONERROR_INVALID => "Invalid configuration.",

      ],
  },
{
      kind: ERRORKIND_CERTIFICATE,
      sym: CertificateError,
      desc: "Certificate errors.",
      values: [
        CERTIFICATEERROR_MALFORMED => "Malformed certificate.",
CERTIFICATEERROR_EXPIRED => "Expired certificate.",
CERTIFICATEERROR_NOT_FOUND => "Certificate not found.",
CERTIFICATEERROR_UNKNOWN => "Unknown error. Can wrap a SystemError.",
CERTIFICATEERROR_UNSUPPORTED => "Certificate not supported by the underlying implementation.",

      ],
  },
{
      kind: ERRORKIND_PRIVATE_KEY,
      sym: PrivateKeyError,
      desc: "Private key errors.",
      values: [
        PRIVATEKEYERROR_MALFORMED => "Malformed private key.",
PRIVATEKEYERROR_NOT_FOUND => "Private key not found.",
PRIVATEKEYERROR_UNKNOWN => "Unknown error. Can wrap a SystemError.",
PRIVATEKEYERROR_UNSUPPORTED => "Certificate not supported by the underlying implementation.",
PRIVATEKEYERROR_NOT_SERVER => "Not a server configuration.",

      ],
  },
{
      kind: ERRORKIND_ASN1,
      sym: ASN1Error,
      desc: "ASN.1 errors.",
      values: [
        ASN1ERROR_INVALID_FORMAT => "Invalid format.",
ASN1ERROR_MALFORMED => "Malformed ASN.1 document.",

      ],
  },
{
      kind: ERRORKIND_ALPN,
      sym: ALPNError,
      desc: "ALPN errors.",
      values: [
        ALPNERROR_LENGTH_ERROR => "Protocol length is longer than 255 bytes.",
ALPNERROR_INVALID_STRING => "Protocol contains &#39;\x00&#39; byte or invalid string.",

      ],
  },
{
      kind: ERRORKIND_DATA_SOURCE,
      sym: DataSourceError,
      desc: "DataSource errors.",
      values: [
        DATASOURCEERROR_EMPTY => "Empty data source.",
DATASOURCEERROR_INVALID_CASE => "Invalid case for data source.",
DATASOURCEERROR_NOT_FOUND => "Data not found on local filesystem.",

      ],
  },
{
      kind: ERRORKIND_KEM,
      sym: KEMError,
      desc: "KEM errors.",
      values: [
        KEMERROR_INVALID => "Invalid or unsupported KEM.",
KEMERROR_TOO_MANY => "Too many KEMs.",

      ],
  },
{
      kind: ERRORKIND_SYSTEM,
      sym: SystemError,
      desc: "System errors.",
      values: [
        SYSTEMERROR_MEMORY => "Memory error (e.g. allocation failed).",
SYSTEMERROR_INTEGER_OVERFLOW => "Integer overflow.",
SYSTEMERROR_BACKEND => "Backend error.",

      ],
  },
{
      kind: ERRORKIND_SOCKET,
      sym: SocketError,
      desc: "Socket errors.
 These errors are used in io/socket.",
      values: [
        SOCKETERROR_BAD_FD => "Bad file descriptor.",
SOCKETERROR_CREATION_FAILED => "Socket creation failed.",
SOCKETERROR_BAD_NETADDR => "Invalid network address.",
SOCKETERROR_NETADDR_UNKNOWN => "Failed to resolve network address.",
SOCKETERROR_FSTAT_FAILED => "Syscall &#39;fstat&#39; failed.",
SOCKETERROR_NOT_SOCK => "File descriptor is not a socket.",
SOCKETERROR_GETSOCKNAME_FAILED => "Syscall getsockname failed.",
SOCKETERROR_SETSOCKOPT_FAILED => "Syscall setsockopt failed.",
SOCKETERROR_INVALID_AI_FAMILY => "Invalid AI family.",

      ],
  },
{
      kind: ERRORKIND_HANDSHAKE,
      sym: HandshakeError,
      desc: "",
      values: [
        HANDSHAKEERROR_INVALID_SERVER_NAME => "Invalid Server Name.",
HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED => "Certficate verification failed.",
HANDSHAKEERROR_CERTIFICATE_EXPIRED => "Certificate has expired.",
HANDSHAKEERROR_CERTIFICATE_REVOKED => "Certificate was revoked.",
HANDSHAKEERROR_INVALID_CERTIFICATE => "Invalid Certificate.",
HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED => "Signature verification error.",
HANDSHAKEERROR_DEPTH_EXCEEDED => "Certificate chain too long or pathlen exceeded.",
HANDSHAKEERROR_UNSUPPORTED_PROTOCOL => "Unsupported protocol.",
HANDSHAKEERROR_NO_SHARED_CIPHER => "No shared cipher.",
HANDSHAKEERROR_NO_SUITABLE_KEY_SHARE => "No suitable key share.",
HANDSHAKEERROR_UNKNOWN_ERROR => "Unknown handshake error.",

      ],
  },
{
      kind: ERRORKIND_TUNNEL,
      sym: TunnelError,
      desc: "Tunnel error.",
      values: [
        TUNNELERROR_INVALID => "Invalid tunnel configuration.",
TUNNELERROR_VERIFIER => "Invalid tunnel verifier.",
TUNNELERROR_UNKNOWN => "Unknown error.",

      ],
  },
);
