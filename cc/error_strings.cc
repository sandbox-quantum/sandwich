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

///
/// \file
/// \brief Error strings API implementation.
///
/// \author thb-sb

#include "cc/error_strings.h"

#include <optional>

namespace saq::sandwich::error {

namespace {

/// \brief API error (APIError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const APIError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case APIError::kConfiguration: {
      return "invalid configuration";
    }
    case APIError::kSocket: {
      return "socket error";
    }
    case APIError::kTunnel: {
      return "tunnel error";
    }
#pragma GCC diagnostic pop
  }

  return std::nullopt;
}

/// \brief Configuration error (ConfigurationError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const ConfigurationError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case ConfigurationError::kInvalidImplementation: {
      return "invalid implementation";
    }
    case ConfigurationError::kUnsupportedImplementation: {
      return "unsupported implementation";
    }
    case ConfigurationError::kInvalid: {
      return "invalid configuration";
    }
#pragma GCC diagnostic pop
  }

  return std::nullopt;
}

/// \brief OpenSSL configuration error (OpenSSLConfigurationError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const OpenSSLConfigurationError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case OpenSSLConfigurationError::kEmpty: {
      return "empty configuration";
    }
    case OpenSSLConfigurationError::kInvalidCase: {
      return "invalid oneof case";
    }
    case OpenSSLConfigurationError::kUnsupportedImplementation: {
      return "unsupported implementation";
    }
    case OpenSSLConfigurationError::kUnsupportedProtocolVersion: {
      return "unsupported TLS version";
    }
    case OpenSSLConfigurationError::kInvalid: {
      return "invalid OpenSSL configuration";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief OpenSSL client configuration error (OpenSSLClientConfigurationError)
/// to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const OpenSSLClientConfigurationError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case OpenSSLClientConfigurationError::kEmpty: {
      return "empty configuration";
    }
    case OpenSSLClientConfigurationError::kCertificate: {
      return "certificate error";
    };
    case OpenSSLClientConfigurationError::kSslCtxFailed: {
      return "SSL_CTX* creation failed";
    }
    case OpenSSLClientConfigurationError::kKem: {
      return "KEM error";
    }
    case OpenSSLClientConfigurationError::kFlags: {
      return "flags error";
    }
    case OpenSSLClientConfigurationError::kSslFailed: {
      return "SSL* creation failed";
    }
    case OpenSSLClientConfigurationError::kBioFailed: {
      return "BIO* creation failed";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief OpenSSL server configuration error (OpenSSLServerConfigurationError)
/// to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const OpenSSLServerConfigurationError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case OpenSSLServerConfigurationError::kEmpty: {
      return "empty configuration";
    }
    case OpenSSLServerConfigurationError::kCertificate: {
      return "certificate error";
    };
    case OpenSSLServerConfigurationError::kSslCtxFailed: {
      return "SSL_CTX* creation failed";
    }
    case OpenSSLServerConfigurationError::kKem: {
      return "KEM error";
    }
    case OpenSSLServerConfigurationError::kFlags: {
      return "flags error";
    }
    case OpenSSLServerConfigurationError::kPrivateKey: {
      return "private key error";
    }
    case OpenSSLServerConfigurationError::kSslFailed: {
      return "SSL* creation failed";
    }
    case OpenSSLServerConfigurationError::kBioFailed: {
      return "BIO* creation failed";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief Certificate error (CertificateError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const CertificateError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case CertificateError::kExpired: {
      return "certificate expired";
    }
    case CertificateError::kMalformed: {
      return "certificate malformed";
    }
    case CertificateError::kNotFound: {
      return "certificate not found on disk";
    }
    case CertificateError::kUnknown: {
      return "unknown error";
    }
    case CertificateError::kUnsupported: {
      return "certificate not supported by underlying implementation";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief Private keyerror (PrivateKeyError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const PrivateKeyError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case PrivateKeyError::kMalformed: {
      return "private key malformed";
    }
    case PrivateKeyError::kNotFound: {
      return "private key not found on disk";
    }
    case PrivateKeyError::kUnknown: {
      return "unknown error";
    }
    case PrivateKeyError::kUnsupported: {
      return "private key not supported by underlying implementation";
    }
    case PrivateKeyError::kNotServer: {
      return "not a server configuration";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief System error (SystemError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const SystemError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case SystemError::kMemory: {
      return "memory error";
    }
    case SystemError::kIntegerOverflow: {
      return "integer overflow";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief DataSource error (DataSourceError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const DataSourceError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case DataSourceError::kEmpty: {
      return "empty DataSource";
    }
    case DataSourceError::kInvalidCase: {
      return "invalid oneof case";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief Socket error (SocketError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const SocketError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case SocketError::kBadFd: {
      return "bad file descriptor";
    }
    case SocketError::kCreationFailed: {
      return "socket creation failed";
    }
    case SocketError::kBadNetaddr: {
      return "bad network address";
    }
    case SocketError::kNetaddrUnknown: {
      return "network address resolution failed";
    }
    case SocketError::kFstatFailed: {
      return "fstat failed";
    }
    case SocketError::kNotSock: {
      return "not a socket";
    }
    case SocketError::kGetsocknameFailed: {
      return "getsockname failed";
    }
    case SocketError::kSetsockoptFailed: {
      return "setsockopt failed";
    }
    case SocketError::kInvalidAiFamily: {
      return "invalid AI family";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief Protobuf error (ProtobufError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const ProtobufError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case ProtobufError::kEmpty: {
      return "empty message";
    }
    case ProtobufError::kTooBig: {
      return "message too large";
    }
    case ProtobufError::kParseFailed: {
      return "message parsing failed";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief ASN.1 error (ASN1Error) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const ASN1Error e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case ASN1Error::kInvalidFormat: {
      return "invalid format";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief KEM error (KEMError) to string.
///
/// \param e Error code.
///
/// \return Error string, or std::nullopt.
[[nodiscard]] auto ToString(const KEMError e)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (e) {
    case KEMError::kInvalid: {
      return "invalid or unsupported KEM";
    }
    case KEMError::kTooMany: {
      return "too many KEMs";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

/// \brief Error kind (ErrorKind) to string.
///
/// \param k Error kind
///
/// \return Kind string, or std::nullopt.
[[nodiscard]] auto ToString(const ErrorKind k)
    -> std::optional<std::string_view> {
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (k) {
    case ErrorKind::kApi: {
      return "API error";
    }
    case ErrorKind::kCertificate: {
      return "certificate error";
    }
    case ErrorKind::kConfiguration: {
      return "configuration error";
    }
    case ErrorKind::kOpensslConfiguration: {
      return "OpenSSL configuration error";
    }
    case ErrorKind::kOpensslClientConfiguration: {
      return "OpenSSL client configuration error";
    }
    case ErrorKind::kOpensslServerConfiguration: {
      return "OpenSSL server configuration error";
    }
    case ErrorKind::kSystem: {
      return "system error";
    }
    case ErrorKind::kSocket: {
      return "socket error";
    }
    case ErrorKind::kProtobuf: {
      return "protobuf error";
    }
    case ErrorKind::kPrivateKey: {
      return "private key error";
    }
    case ErrorKind::kAsn1: {
      return "ASN.1 error";
    }
    case ErrorKind::kDataSource: {
      return "DataSource error";
    }
    case ErrorKind::kKem: {
      return "KEM error";
    }
  }
#pragma GCC diagnostic pop

  return std::nullopt;
}

} // end anonymous namespace

constexpr ErrorString::ErrorString() noexcept = default;

ErrorString::ErrorString(const Error &err) noexcept
    : ErrorString(&err.Code()) {}

ErrorString::ErrorString(const ErrorCode *ec) noexcept {
  if (ec == nullptr) {
    kind_ = kNoErrorString;
    code_ = kNoErrorString;
    return;
  }
  const auto kstr = ToString(static_cast<ErrorKind>(ec->kind));
  if (!kstr) {
    return;
  }
  kind_ = *kstr;

  std::optional<std::string_view> cstr = std::nullopt;
  const auto code = ec->code;
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
  switch (static_cast<ErrorKind>(ec->kind)) {
    case ErrorKind::kApi: {
      cstr = ToString(static_cast<APIError>(code));
    } break;
    case ErrorKind::kConfiguration: {
      cstr = ToString(static_cast<ConfigurationError>(code));
    } break;
    case ErrorKind::kOpensslConfiguration: {
      cstr = ToString(static_cast<OpenSSLConfigurationError>(code));
    } break;
    case ErrorKind::kOpensslClientConfiguration: {
      cstr = ToString(static_cast<OpenSSLClientConfigurationError>(code));
    } break;
    case ErrorKind::kCertificate: {
      cstr = ToString(static_cast<CertificateError>(code));
    } break;
    case ErrorKind::kSystem: {
      cstr = ToString(static_cast<SystemError>(code));
    } break;
    case ErrorKind::kSocket: {
      cstr = ToString(static_cast<SocketError>(code));
    } break;
    case ErrorKind::kProtobuf: {
      cstr = ToString(static_cast<ProtobufError>(code));
    } break;
    case ErrorKind::kOpensslServerConfiguration: {
      cstr = ToString(static_cast<OpenSSLServerConfigurationError>(code));
    } break;
    case ErrorKind::kPrivateKey: {
      cstr = ToString(static_cast<PrivateKeyError>(code));
    } break;
    case ErrorKind::kAsn1: {
      cstr = ToString(static_cast<ASN1Error>(code));
    } break;
    case ErrorKind::kDataSource: {
      cstr = ToString(static_cast<DataSourceError>(code));
    } break;
    case ErrorKind::kKem: {
      cstr = ToString(static_cast<KEMError>(code));
    }
  }
#pragma GCC diagnostic pop
  code_ = cstr.value_or(kUnknownErrorCodeString);
}

auto ErrorString::Kind() const noexcept -> const std::string_view & {
  return kind_;
}

auto ErrorString::Code() const noexcept -> const std::string_view & {
  return code_;
}

auto ErrorString::operator<<(std::ostream &os) const noexcept -> decltype(os) {
  return os << kind_ << ": " << code_;
}

auto operator<<(std::ostream &os, const ErrorString &es) -> std::ostream & {
  return es.operator<<(os);
}

auto operator<<(std::ostream &os, const ErrorCode &ec) -> std::ostream & {
  const ErrorString err{&ec};
  return err.operator<<(os);
}

auto GetStringError(const error::Error &err) -> ErrorString {
  return ErrorString{err};
}

auto GetStringError(const enum tunnel::RecordError err) -> std::string_view {
  switch (err) {
    case tunnel::RecordError::kOk: {
      return "no error";
    }
    case tunnel::RecordError::kWantRead: {
      return "wants to read data, but the underlying I/O interface is "
             "non-blocking";
    }
    case tunnel::RecordError::kWantWrite: {
      return "wants to write data, but the underlying I/O interface is "
             "non-blocking";
    }
    case tunnel::RecordError::kBeingShutdown: {
      return "tunnel is being close";
    }
    case tunnel::RecordError::kClosed: {
      return "tunnel is closed";
    }
    case tunnel::RecordError::kUnknown: {
      return "unknown error";
    }
    default: {
      return "unknown record plane error code";
    }
  }
}

auto GetStringError(const enum io::IOError err) -> std::string_view {
  switch (err) {
    case io::IOError::kOk: {
      return "no error";
    }
    case io::IOError::kInProgress: {
      return "connection in progress";
    }
    case io::IOError::kWouldBlock: {
      return "the i/o operation would block";
    }
    case io::IOError::kRefused: {
      return "the I/O interface has been refused connection";
    }
    case io::IOError::kClosed: {
      return "the I/O interface is closed";
    }
    case io::IOError::kInvalid: {
      return "the I/O interface isn't valid";
    }
    case io::IOError::kUnknown: {
      return "the I/O interface raised an unknown error";
    }
    default: {
      return "unknown IO error code";
    }
  }
}

auto GetStringError(const enum tunnel::State err) -> std::string_view {
  switch (err) {
    case tunnel::State::kNotConnected: {
      return "not connected";
    }
    case tunnel::State::kConnectionInProgress: {
      return "connection in progress";
    }
    case tunnel::State::kHandshakeInProgress: {
      return "handshake in progress";
    }
    case tunnel::State::kHandshakeDone: {
      return "handshake done";
    }
    case tunnel::State::kBeingShutdown: {
      return "being shutdown";
    }
    case tunnel::State::kDisconnected: {
      return "disconnected";
    }
    case tunnel::State::kError: {
      return "error";
    }
    default: {
      return "unknown tunnel state code";
    }
  }
}

auto GetStringError(const enum tunnel::HandshakeState err) -> std::string_view {
  switch (err) {
    case tunnel::HandshakeState::kInProgress: {
      return "in progress";
    }
    case tunnel::HandshakeState::kDone: {
      return "done";
    }
    case tunnel::HandshakeState::kWantRead: {
      return "the implementation wants to read from the wire, but the "
             "underlying I/O is non-blocking";
    }
    case tunnel::HandshakeState::kWantWrite: {
      return "the implementation wants to write to the wire, but the "
             "underlying I/O is non-blocking";
    }
    case tunnel::HandshakeState::kError: {
      return "a critical error occurred";
    }
    default: {
      return "unknown handshake state code";
    }
  }
}

} // end namespace saq::sandwich::error
