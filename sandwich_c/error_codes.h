// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * \file
 * \brief Sandwich errors specification
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


/** \brief Enum APIError. */
enum SandwichAPIError { 
  SANDWICH_APIERROR_CONFIGURATION = 0,
  SANDWICH_APIERROR_SOCKET = 1,
  SANDWICH_APIERROR_TUNNEL = 2,
};
typedef enum SandwichAPIError SandwichAPIError;

/** \brief Enum ConfigurationError. */
enum SandwichConfigurationError { 
  SANDWICH_CONFIGURATIONERROR_INVALID_IMPLEMENTATION = 0,
  SANDWICH_CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION = 1,
  SANDWICH_CONFIGURATIONERROR_INVALID = 2,
  SANDWICH_CONFIGURATIONERROR_INVALID_LISTENER = 3,
};
typedef enum SandwichConfigurationError SandwichConfigurationError;

/** \brief Enum ProtobufError. */
enum SandwichProtobufError { 
  SANDWICH_PROTOBUFERROR_EMPTY = 0,
  SANDWICH_PROTOBUFERROR_TOO_BIG = 1,
  SANDWICH_PROTOBUFERROR_PARSE_FAILED = 2,
  SANDWICH_PROTOBUFERROR_NULLPTR = 3,
  SANDWICH_PROTOBUFERROR_INVALID_ARGUMENT = 4,
};
typedef enum SandwichProtobufError SandwichProtobufError;

/** \brief Enum TLSConfigurationError. */
enum SandwichTLSConfigurationError { 
  SANDWICH_TLSCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION = 0,
  SANDWICH_TLSCONFIGURATIONERROR_INVALID_CASE = 1,
  SANDWICH_TLSCONFIGURATIONERROR_EMPTY = 2,
  SANDWICH_TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION = 3,
  SANDWICH_TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE = 4,
  SANDWICH_TLSCONFIGURATIONERROR_INVALID = 5,
};
typedef enum SandwichTLSConfigurationError SandwichTLSConfigurationError;

/** \brief Enum CertificateError. */
enum SandwichCertificateError { 
  SANDWICH_CERTIFICATEERROR_MALFORMED = 0,
  SANDWICH_CERTIFICATEERROR_EXPIRED = 1,
  SANDWICH_CERTIFICATEERROR_NOT_FOUND = 2,
  SANDWICH_CERTIFICATEERROR_UNKNOWN = 3,
  SANDWICH_CERTIFICATEERROR_UNSUPPORTED = 4,
};
typedef enum SandwichCertificateError SandwichCertificateError;

/** \brief Enum PrivateKeyError. */
enum SandwichPrivateKeyError { 
  SANDWICH_PRIVATEKEYERROR_MALFORMED = 0,
  SANDWICH_PRIVATEKEYERROR_NOT_FOUND = 1,
  SANDWICH_PRIVATEKEYERROR_UNKNOWN = 2,
  SANDWICH_PRIVATEKEYERROR_UNSUPPORTED = 3,
  SANDWICH_PRIVATEKEYERROR_NOT_SERVER = 4,
};
typedef enum SandwichPrivateKeyError SandwichPrivateKeyError;

/** \brief Enum ASN1Error. */
enum SandwichASN1Error { 
  SANDWICH_ASN1ERROR_INVALID_FORMAT = 0,
  SANDWICH_ASN1ERROR_MALFORMED = 1,
};
typedef enum SandwichASN1Error SandwichASN1Error;

/** \brief Enum ALPNError. */
enum SandwichALPNError { 
  SANDWICH_ALPNERROR_LENGTH_ERROR = 0,
  SANDWICH_ALPNERROR_INVALID_STRING = 1,
};
typedef enum SandwichALPNError SandwichALPNError;

/** \brief Enum DataSourceError. */
enum SandwichDataSourceError { 
  SANDWICH_DATASOURCEERROR_EMPTY = 0,
  SANDWICH_DATASOURCEERROR_INVALID_CASE = 1,
  SANDWICH_DATASOURCEERROR_NOT_FOUND = 2,
};
typedef enum SandwichDataSourceError SandwichDataSourceError;

/** \brief Enum KEMError. */
enum SandwichKEMError { 
  SANDWICH_KEMERROR_INVALID = 0,
  SANDWICH_KEMERROR_TOO_MANY = 1,
};
typedef enum SandwichKEMError SandwichKEMError;

/** \brief Enum SystemError. */
enum SandwichSystemError { 
  SANDWICH_SYSTEMERROR_MEMORY = 0,
  SANDWICH_SYSTEMERROR_INTEGER_OVERFLOW = 1,
};
typedef enum SandwichSystemError SandwichSystemError;

/** \brief Enum SocketError. */
enum SandwichSocketError { 
  SANDWICH_SOCKETERROR_BAD_FD = 0,
  SANDWICH_SOCKETERROR_CREATION_FAILED = 1,
  SANDWICH_SOCKETERROR_BAD_NETADDR = 2,
  SANDWICH_SOCKETERROR_NETADDR_UNKNOWN = 3,
  SANDWICH_SOCKETERROR_FSTAT_FAILED = 4,
  SANDWICH_SOCKETERROR_NOT_SOCK = 5,
  SANDWICH_SOCKETERROR_GETSOCKNAME_FAILED = 6,
  SANDWICH_SOCKETERROR_SETSOCKOPT_FAILED = 7,
  SANDWICH_SOCKETERROR_INVALID_AI_FAMILY = 8,
};
typedef enum SandwichSocketError SandwichSocketError;

/** \brief Enum HandshakeError. */
enum SandwichHandshakeError { 
  SANDWICH_HANDSHAKEERROR_INVALID_SERVER_NAME = 0,
  SANDWICH_HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED = 1,
  SANDWICH_HANDSHAKEERROR_CERTIFICATE_EXPIRED = 2,
  SANDWICH_HANDSHAKEERROR_CERTIFICATE_REVOKED = 3,
  SANDWICH_HANDSHAKEERROR_INVALID_CERTIFICATE = 4,
  SANDWICH_HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED = 5,
  SANDWICH_HANDSHAKEERROR_UNKNOWN_ERROR = 6,
};
typedef enum SandwichHandshakeError SandwichHandshakeError;

/** \brief Enum TunnelError. */
enum SandwichTunnelError { 
  SANDWICH_TUNNELERROR_INVALID = 0,
  SANDWICH_TUNNELERROR_VERIFIER = 1,
  SANDWICH_TUNNELERROR_UNKNOWN = 2,
};
typedef enum SandwichTunnelError SandwichTunnelError;

/** \brief Enum ErrorKind. */
enum SandwichErrorKind { 
  SANDWICH_ERRORKIND_API = 0,
  SANDWICH_ERRORKIND_CONFIGURATION = 1,
  SANDWICH_ERRORKIND_TLS_CONFIGURATION = 2,
  SANDWICH_ERRORKIND_CERTIFICATE = 3,
  SANDWICH_ERRORKIND_SYSTEM = 4,
  SANDWICH_ERRORKIND_SOCKET = 5,
  SANDWICH_ERRORKIND_PROTOBUF = 6,
  SANDWICH_ERRORKIND_PRIVATE_KEY = 7,
  SANDWICH_ERRORKIND_ASN1 = 8,
  SANDWICH_ERRORKIND_DATA_SOURCE = 9,
  SANDWICH_ERRORKIND_KEM = 10,
  SANDWICH_ERRORKIND_HANDSHAKE = 11,
  SANDWICH_ERRORKIND_TUNNEL = 12,
  SANDWICH_ERRORKIND_ALPN = 13,
  SANDWICH_ERRORKIND_IO = 14,
};
typedef enum SandwichErrorKind SandwichErrorKind;


#ifdef __cplusplus
} // end extern "C"
#endif
