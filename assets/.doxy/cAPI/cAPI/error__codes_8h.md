

# File error\_codes.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**error\_codes.h**](error__codes_8h.md)

[Go to the source code of this file](error__codes_8h_source.md)

_Sandwich errors specification._ 


















## Public Types

| Type | Name |
| ---: | :--- |
| enum  | [**SandwichALPNError**](#enum-sandwichalpnerror)  <br>_Enum ALPNError._  |
| typedef enum [**SandwichALPNError**](error__codes_8h.md#enum-sandwichalpnerror) | [**SandwichALPNError**](#typedef-sandwichalpnerror)  <br> |
| enum  | [**SandwichAPIError**](#enum-sandwichapierror)  <br>_Enum APIError._  |
| typedef enum [**SandwichAPIError**](error__codes_8h.md#enum-sandwichapierror) | [**SandwichAPIError**](#typedef-sandwichapierror)  <br> |
| enum  | [**SandwichASN1Error**](#enum-sandwichasn1error)  <br>_Enum ASN1Error._  |
| typedef enum [**SandwichASN1Error**](error__codes_8h.md#enum-sandwichasn1error) | [**SandwichASN1Error**](#typedef-sandwichasn1error)  <br> |
| enum  | [**SandwichCertificateError**](#enum-sandwichcertificateerror)  <br>_Enum CertificateError._  |
| typedef enum [**SandwichCertificateError**](error__codes_8h.md#enum-sandwichcertificateerror) | [**SandwichCertificateError**](#typedef-sandwichcertificateerror)  <br> |
| enum  | [**SandwichConfigurationError**](#enum-sandwichconfigurationerror)  <br>_Enum ConfigurationError._  |
| typedef enum [**SandwichConfigurationError**](error__codes_8h.md#enum-sandwichconfigurationerror) | [**SandwichConfigurationError**](#typedef-sandwichconfigurationerror)  <br> |
| enum  | [**SandwichDataSourceError**](#enum-sandwichdatasourceerror)  <br>_Enum DataSourceError._  |
| typedef enum [**SandwichDataSourceError**](error__codes_8h.md#enum-sandwichdatasourceerror) | [**SandwichDataSourceError**](#typedef-sandwichdatasourceerror)  <br> |
| enum  | [**SandwichErrorKind**](#enum-sandwicherrorkind)  <br>_Enum ErrorKind._  |
| typedef enum [**SandwichErrorKind**](error__codes_8h.md#enum-sandwicherrorkind) | [**SandwichErrorKind**](#typedef-sandwicherrorkind)  <br> |
| enum  | [**SandwichHandshakeError**](#enum-sandwichhandshakeerror)  <br>_Enum HandshakeError._  |
| typedef enum [**SandwichHandshakeError**](error__codes_8h.md#enum-sandwichhandshakeerror) | [**SandwichHandshakeError**](#typedef-sandwichhandshakeerror)  <br> |
| enum  | [**SandwichKEMError**](#enum-sandwichkemerror)  <br>_Enum KEMError._  |
| typedef enum [**SandwichKEMError**](error__codes_8h.md#enum-sandwichkemerror) | [**SandwichKEMError**](#typedef-sandwichkemerror)  <br> |
| enum  | [**SandwichPrivateKeyError**](#enum-sandwichprivatekeyerror)  <br>_Enum PrivateKeyError._  |
| typedef enum [**SandwichPrivateKeyError**](error__codes_8h.md#enum-sandwichprivatekeyerror) | [**SandwichPrivateKeyError**](#typedef-sandwichprivatekeyerror)  <br> |
| enum  | [**SandwichProtobufError**](#enum-sandwichprotobuferror)  <br>_Enum ProtobufError._  |
| typedef enum [**SandwichProtobufError**](error__codes_8h.md#enum-sandwichprotobuferror) | [**SandwichProtobufError**](#typedef-sandwichprotobuferror)  <br> |
| enum  | [**SandwichSocketError**](#enum-sandwichsocketerror)  <br>_Enum SocketError._  |
| typedef enum [**SandwichSocketError**](error__codes_8h.md#enum-sandwichsocketerror) | [**SandwichSocketError**](#typedef-sandwichsocketerror)  <br> |
| enum  | [**SandwichSystemError**](#enum-sandwichsystemerror)  <br>_Enum SystemError._  |
| typedef enum [**SandwichSystemError**](error__codes_8h.md#enum-sandwichsystemerror) | [**SandwichSystemError**](#typedef-sandwichsystemerror)  <br> |
| enum  | [**SandwichTLSConfigurationError**](#enum-sandwichtlsconfigurationerror)  <br>_Enum TLSConfigurationError._  |
| typedef enum [**SandwichTLSConfigurationError**](error__codes_8h.md#enum-sandwichtlsconfigurationerror) | [**SandwichTLSConfigurationError**](#typedef-sandwichtlsconfigurationerror)  <br> |
| enum  | [**SandwichTunnelError**](#enum-sandwichtunnelerror)  <br>_Enum TunnelError._  |
| typedef enum [**SandwichTunnelError**](error__codes_8h.md#enum-sandwichtunnelerror) | [**SandwichTunnelError**](#typedef-sandwichtunnelerror)  <br> |
















































## Public Types Documentation




### enum SandwichALPNError 

```C++
enum SandwichALPNError {
    SANDWICH_ALPNERROR_LENGTH_ERROR = 0,
    SANDWICH_ALPNERROR_INVALID_STRING = 1
};
```






### typedef SandwichALPNError 

```C++
typedef enum SandwichALPNError SandwichALPNError;
```






### enum SandwichAPIError 

```C++
enum SandwichAPIError {
    SANDWICH_APIERROR_CONFIGURATION = 0,
    SANDWICH_APIERROR_SOCKET = 1,
    SANDWICH_APIERROR_TUNNEL = 2
};
```






### typedef SandwichAPIError 

```C++
typedef enum SandwichAPIError SandwichAPIError;
```






### enum SandwichASN1Error 

```C++
enum SandwichASN1Error {
    SANDWICH_ASN1ERROR_INVALID_FORMAT = 0,
    SANDWICH_ASN1ERROR_MALFORMED = 1
};
```






### typedef SandwichASN1Error 

```C++
typedef enum SandwichASN1Error SandwichASN1Error;
```






### enum SandwichCertificateError 

```C++
enum SandwichCertificateError {
    SANDWICH_CERTIFICATEERROR_MALFORMED = 0,
    SANDWICH_CERTIFICATEERROR_EXPIRED = 1,
    SANDWICH_CERTIFICATEERROR_NOT_FOUND = 2,
    SANDWICH_CERTIFICATEERROR_UNKNOWN = 3,
    SANDWICH_CERTIFICATEERROR_UNSUPPORTED = 4
};
```






### typedef SandwichCertificateError 

```C++
typedef enum SandwichCertificateError SandwichCertificateError;
```






### enum SandwichConfigurationError 

```C++
enum SandwichConfigurationError {
    SANDWICH_CONFIGURATIONERROR_INVALID_IMPLEMENTATION = 0,
    SANDWICH_CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION = 1,
    SANDWICH_CONFIGURATIONERROR_INVALID = 2,
    SANDWICH_CONFIGURATIONERROR_INVALID_LISTENER = 3
};
```






### typedef SandwichConfigurationError 

```C++
typedef enum SandwichConfigurationError SandwichConfigurationError;
```






### enum SandwichDataSourceError 

```C++
enum SandwichDataSourceError {
    SANDWICH_DATASOURCEERROR_EMPTY = 0,
    SANDWICH_DATASOURCEERROR_INVALID_CASE = 1,
    SANDWICH_DATASOURCEERROR_NOT_FOUND = 2
};
```






### typedef SandwichDataSourceError 

```C++
typedef enum SandwichDataSourceError SandwichDataSourceError;
```






### enum SandwichErrorKind 

```C++
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
    SANDWICH_ERRORKIND_IO = 14
};
```






### typedef SandwichErrorKind 

```C++
typedef enum SandwichErrorKind SandwichErrorKind;
```






### enum SandwichHandshakeError 

```C++
enum SandwichHandshakeError {
    SANDWICH_HANDSHAKEERROR_INVALID_SERVER_NAME = 0,
    SANDWICH_HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED = 1,
    SANDWICH_HANDSHAKEERROR_CERTIFICATE_EXPIRED = 2,
    SANDWICH_HANDSHAKEERROR_CERTIFICATE_REVOKED = 3,
    SANDWICH_HANDSHAKEERROR_INVALID_CERTIFICATE = 4,
    SANDWICH_HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED = 5,
    SANDWICH_HANDSHAKEERROR_UNKNOWN_ERROR = 6,
    SANDWICH_HANDSHAKEERROR_DEPTH_EXCEEDED = 7,
    SANDWICH_HANDSHAKEERROR_UNSUPPORTED_PROTOCOL = 8,
    SANDWICH_HANDSHAKEERROR_NO_SHARED_CIPHER = 9,
    SANDWICH_HANDSHAKEERROR_NO_SUITABLE_KEY_SHARE = 10
};
```






### typedef SandwichHandshakeError 

```C++
typedef enum SandwichHandshakeError SandwichHandshakeError;
```






### enum SandwichKEMError 

```C++
enum SandwichKEMError {
    SANDWICH_KEMERROR_INVALID = 0,
    SANDWICH_KEMERROR_TOO_MANY = 1
};
```






### typedef SandwichKEMError 

```C++
typedef enum SandwichKEMError SandwichKEMError;
```






### enum SandwichPrivateKeyError 

```C++
enum SandwichPrivateKeyError {
    SANDWICH_PRIVATEKEYERROR_MALFORMED = 0,
    SANDWICH_PRIVATEKEYERROR_NOT_FOUND = 1,
    SANDWICH_PRIVATEKEYERROR_UNKNOWN = 2,
    SANDWICH_PRIVATEKEYERROR_UNSUPPORTED = 3,
    SANDWICH_PRIVATEKEYERROR_NOT_SERVER = 4
};
```






### typedef SandwichPrivateKeyError 

```C++
typedef enum SandwichPrivateKeyError SandwichPrivateKeyError;
```






### enum SandwichProtobufError 

```C++
enum SandwichProtobufError {
    SANDWICH_PROTOBUFERROR_EMPTY = 0,
    SANDWICH_PROTOBUFERROR_TOO_BIG = 1,
    SANDWICH_PROTOBUFERROR_PARSE_FAILED = 2,
    SANDWICH_PROTOBUFERROR_NULLPTR = 3,
    SANDWICH_PROTOBUFERROR_INVALID_ARGUMENT = 4
};
```






### typedef SandwichProtobufError 

```C++
typedef enum SandwichProtobufError SandwichProtobufError;
```






### enum SandwichSocketError 

```C++
enum SandwichSocketError {
    SANDWICH_SOCKETERROR_BAD_FD = 0,
    SANDWICH_SOCKETERROR_CREATION_FAILED = 1,
    SANDWICH_SOCKETERROR_BAD_NETADDR = 2,
    SANDWICH_SOCKETERROR_NETADDR_UNKNOWN = 3,
    SANDWICH_SOCKETERROR_FSTAT_FAILED = 4,
    SANDWICH_SOCKETERROR_NOT_SOCK = 5,
    SANDWICH_SOCKETERROR_GETSOCKNAME_FAILED = 6,
    SANDWICH_SOCKETERROR_SETSOCKOPT_FAILED = 7,
    SANDWICH_SOCKETERROR_INVALID_AI_FAMILY = 8
};
```






### typedef SandwichSocketError 

```C++
typedef enum SandwichSocketError SandwichSocketError;
```






### enum SandwichSystemError 

```C++
enum SandwichSystemError {
    SANDWICH_SYSTEMERROR_MEMORY = 0,
    SANDWICH_SYSTEMERROR_INTEGER_OVERFLOW = 1,
    SANDWICH_SYSTEMERROR_BACKEND = 2
};
```






### typedef SandwichSystemError 

```C++
typedef enum SandwichSystemError SandwichSystemError;
```






### enum SandwichTLSConfigurationError 

```C++
enum SandwichTLSConfigurationError {
    SANDWICH_TLSCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION = 0,
    SANDWICH_TLSCONFIGURATIONERROR_INVALID_CASE = 1,
    SANDWICH_TLSCONFIGURATIONERROR_EMPTY = 2,
    SANDWICH_TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION = 3,
    SANDWICH_TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE = 4,
    SANDWICH_TLSCONFIGURATIONERROR_INVALID = 5,
    SANDWICH_TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE = 6,
    SANDWICH_TLSCONFIGURATIONERROR_UNSUPPORTED_CONTROL_CHARACTERS = 7
};
```






### typedef SandwichTLSConfigurationError 

```C++
typedef enum SandwichTLSConfigurationError SandwichTLSConfigurationError;
```






### enum SandwichTunnelError 

```C++
enum SandwichTunnelError {
    SANDWICH_TUNNELERROR_INVALID = 0,
    SANDWICH_TUNNELERROR_VERIFIER = 1,
    SANDWICH_TUNNELERROR_UNKNOWN = 2
};
```






### typedef SandwichTunnelError 

```C++
typedef enum SandwichTunnelError SandwichTunnelError;
```




------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/error_codes.h`

