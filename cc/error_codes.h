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
/// \brief Sandwich errors specification

#pragma once

namespace saq::sandwich::error {


/// \brief Enum APIError.
enum class APIError : int { 
  kConfiguration = 0,
  kSocket = 1,
  kTunnel = 2,
};

/// \brief Enum ConfigurationError.
enum class ConfigurationError : int { 
  kInvalidImplementation = 0,
  kUnsupportedImplementation = 1,
  kInvalid = 2,
};

/// \brief Enum ProtobufError.
enum class ProtobufError : int { 
  kEmpty = 0,
  kTooBig = 1,
  kParseFailed = 2,
};

/// \brief Enum OpenSSLConfigurationError.
enum class OpenSSLConfigurationError : int { 
  kUnsupportedImplementation = 0,
  kInvalidCase = 1,
  kEmpty = 2,
  kUnsupportedProtocolVersion = 3,
  kInvalid = 4,
};

/// \brief Enum OpenSSLClientConfigurationError.
enum class OpenSSLClientConfigurationError : int { 
  kEmpty = 0,
  kSslCtxFailed = 1,
  kCertificate = 2,
  kKem = 3,
  kFlags = 4,
  kSslFailed = 5,
  kBioFailed = 6,
};

/// \brief Enum OpenSSLServerConfigurationError.
enum class OpenSSLServerConfigurationError : int { 
  kEmpty = 0,
  kSslCtxFailed = 1,
  kCertificate = 2,
  kKem = 3,
  kFlags = 4,
  kPrivateKey = 5,
  kSslFailed = 6,
  kBioFailed = 7,
};

/// \brief Enum CertificateError.
enum class CertificateError : int { 
  kMalformed = 0,
  kExpired = 1,
  kNotFound = 2,
  kUnknown = 3,
  kUnsupported = 4,
};

/// \brief Enum PrivateKeyError.
enum class PrivateKeyError : int { 
  kMalformed = 0,
  kNotFound = 1,
  kUnknown = 2,
  kUnsupported = 3,
  kNotServer = 4,
};

/// \brief Enum ASN1Error.
enum class ASN1Error : int { 
  kInvalidFormat = 0,
};

/// \brief Enum DataSourceError.
enum class DataSourceError : int { 
  kEmpty = 0,
  kInvalidCase = 1,
};

/// \brief Enum KEMError.
enum class KEMError : int { 
  kInvalid = 0,
  kTooMany = 1,
};

/// \brief Enum SystemError.
enum class SystemError : int { 
  kMemory = 0,
  kIntegerOverflow = 1,
};

/// \brief Enum SocketError.
enum class SocketError : int { 
  kBadFd = 0,
  kCreationFailed = 1,
  kBadNetaddr = 2,
  kNetaddrUnknown = 3,
  kFstatFailed = 4,
  kNotSock = 5,
  kGetsocknameFailed = 6,
  kSetsockoptFailed = 7,
  kInvalidAiFamily = 8,
};

/// \brief Enum ErrorKind.
enum class ErrorKind : int { 
  kApi = 0,
  kConfiguration = 1,
  kOpensslConfiguration = 2,
  kOpensslClientConfiguration = 3,
  kOpensslServerConfiguration = 4,
  kCertificate = 5,
  kSystem = 6,
  kSocket = 7,
  kProtobuf = 8,
  kPrivateKey = 9,
  kAsn1 = 10,
  kDataSource = 11,
  kKem = 12,
};


} // end namespace saq::sandwich::error
