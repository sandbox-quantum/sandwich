/*
 * Copyright 2023 SandboxAQ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/// \file
/// \brief Structured error API tests suite.
///
/// \author thb-sb

#include "gtest/gtest.h"

#include "cc/error.h"
#include "cc/error_strings.h"

/// \brief Convenient alias to sandwich namespace.
namespace sandwich = saq::sandwich;

/// \brief Convenient alias to sandwich error namespace.
namespace serror = sandwich::error;

/// \brief Test the ErrorCode constructor using a enum value.
TEST(StructuredError_ErrorCode, Constructor) {
  auto *ec = serror::New(serror::CertificateError::kExpired);
  ASSERT_NE(ec, nullptr) << "error::New returned nullptr";
}

/// \brief Test correctness of ErrorCode kind field.
TEST(StructuredError_ErrorCode, CheckKind) {
  auto *ec = serror::New(serror::CertificateError::kExpired);
  ASSERT_NE(ec, nullptr);
  ASSERT_EQ(ec->kind, serror::ErrorKind::kCertificate) << "ErrorKind mismatch";
}

/// \brief Test correctness of ErrorCode code field.
TEST(StructuredError_ErrorCode, CheckCode) {
  auto *ec = serror::New(serror::CertificateError::kExpired);
  ASSERT_NE(ec, nullptr);
  ASSERT_EQ(ec->code, static_cast<int>(serror::CertificateError::kExpired))
      << "int code mismatch";
  ASSERT_EQ(static_cast<serror::CertificateError>(ec->code),
            serror::CertificateError::kExpired)
      << "enum code mismatch";
}

/// \brief Test emptiness of ErrorCode details field for end of chain.
TEST(StructuredError_ErrorCode, CheckNoDetails) {
  auto *ec = serror::New(serror::CertificateError::kExpired);
  ASSERT_NE(ec, nullptr);
  ASSERT_EQ(ec->details, nullptr) << "details not nullptr";
}

/// \brief Test Error empty constructor (aka no error).
TEST(StructuredError_Error, EmptyConstructor) {
  const serror::Error e{};
  ASSERT_FALSE(e);
}

/// \brief Test Error constructor using Ok_t type.
TEST(StructuredError_Error, EmptyConstructorWithOk_t) {
  const serror::Error e = serror::Ok;
  ASSERT_FALSE(e);
}

/// \brief Test Error constructor using an enum value.
TEST(StructuredError_Error, ConstructorWithEnumValue) {
  const serror::Error e{serror::CertificateError::kMalformed};
  ASSERT_TRUE(e);
}

/// \brief Test Error constructor using an ErrorCode.
TEST(StructuredError_Error, ConstructorWithErrorCode) {
  auto *ec = serror::New(serror::CertificateError::kExpired);
  ASSERT_NE(ec, nullptr);
  const serror::Error e{ec};
  ASSERT_TRUE(e);
}

/// \brief Test Error move constructor.
TEST(StructuredError_Error, MoveConstructor) {
  serror::Error e1{serror::CertificateError::kExpired};
  ASSERT_TRUE(e1);
  const serror::Error e2{std::move(e1)};
  ASSERT_TRUE(e2);
}

/// \brief Test Error conversion operator to ErrorCode.
TEST(StructuredError_Error, OperatorErrorCodeRef) {
  const serror::Error e{serror::CertificateError::kExpired};
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(e).kind,
            serror::ErrorKind::kCertificate)
      << "kind mismatch";
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(e).code,
            static_cast<int>(serror::CertificateError::kExpired))
      << "code mismatch";
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(e).details, nullptr)
      << "details not null";
}

/// \brief Test Error encapsulation using operator>> and moved lvalue.
TEST(StructuredError_Error, OperatorStreamErrorMove) {
  serror::Error parent{serror::APIError::kConfiguration};
  serror::Error child{serror::ConfigurationError::kInvalidImplementation};
  const auto chain = child >> std::move(parent);

  static_assert(std::is_same_v<decltype(chain), const serror::Error>);
  ASSERT_TRUE(chain);
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(chain).kind,
            serror::ErrorKind::kApi)
      << "kind mismatch";
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(chain).code,
            static_cast<int>(serror::APIError::kConfiguration))
      << "code mismatch";

  const auto *details = static_cast<const serror::ErrorCode &>(chain).details;

  ASSERT_NE(details, nullptr) << "details null";

  ASSERT_EQ(details->kind, serror::ErrorKind::kConfiguration)
      << "kind mismatch";
  ASSERT_EQ(
      details->code,
      static_cast<int>(serror::ConfigurationError::kInvalidImplementation))
      << "code mismatch";
}

/// \brief Test Error encapsulation using operator>> and rvalue.
TEST(StructuredError_Error, OperatorStreamErrorTempVar) {
  serror::Error child{serror::ConfigurationError::kInvalidImplementation};
  const auto chain = child >> serror::Error{serror::APIError::kConfiguration};

  static_assert(std::is_same_v<decltype(chain), const serror::Error>);
  ASSERT_TRUE(chain);
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(chain).kind,
            serror::ErrorKind::kApi)
      << "kind mismatch";
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(chain).code,
            static_cast<int>(serror::APIError::kConfiguration))
      << "code mismatch";

  const auto *details = static_cast<const serror::ErrorCode &>(chain).details;

  ASSERT_NE(details, nullptr) << "details null";

  ASSERT_EQ(details->kind, serror::ErrorKind::kConfiguration)
      << "kind mismatch";
  ASSERT_EQ(
      details->code,
      static_cast<int>(serror::ConfigurationError::kInvalidImplementation))
      << "code mismatch";
}

/// \brief Test Error encapsulation using operator>> and ErrorCode lvalue.
TEST(StructuredError_Error, OperatorStreamErrorCode) {
  auto *parent = serror::New(serror::APIError::kConfiguration);
  serror::Error child{serror::ConfigurationError::kInvalidImplementation};
  const auto chain = child >> parent;

  static_assert(std::is_same_v<decltype(chain), const serror::Error>);
  ASSERT_TRUE(chain);
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(chain).kind,
            serror::ErrorKind::kApi)
      << "kind mismatch";
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(chain).code,
            static_cast<int>(serror::APIError::kConfiguration))
      << "code mismatch";

  const auto *details = static_cast<const serror::ErrorCode &>(chain).details;

  ASSERT_NE(details, nullptr) << "details null";

  ASSERT_EQ(details->kind, serror::ErrorKind::kConfiguration)
      << "kind mismatch";
  ASSERT_EQ(
      details->code,
      static_cast<int>(serror::ConfigurationError::kInvalidImplementation))
      << "code mismatch";
}

/// \brief Test Error encapsulation using operator>> and enum value.
TEST(StructuredError_Error, OperatorStreamEnumValue) {
  serror::Error child{serror::ConfigurationError::kInvalidImplementation};
  const auto chain = child >> serror::APIError::kConfiguration;

  static_assert(std::is_same_v<decltype(chain), const serror::Error>);
  ASSERT_TRUE(chain);
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(chain).kind,
            serror::ErrorKind::kApi)
      << "kind mismatch";
  ASSERT_EQ(static_cast<const serror::ErrorCode &>(chain).code,
            static_cast<int>(serror::APIError::kConfiguration))
      << "code mismatch";

  const auto *details = static_cast<const serror::ErrorCode &>(chain).details;

  ASSERT_NE(details, nullptr) << "details null";

  ASSERT_EQ(details->kind, serror::ErrorKind::kConfiguration)
      << "kind mismatch";
  ASSERT_EQ(
      details->code,
      static_cast<int>(serror::ConfigurationError::kInvalidImplementation))
      << "code mismatch";
}

/// \brief Test Error Release method.
TEST(StructuredError_Error, Release) {
  serror::Error e = serror::APIError::kConfiguration;
  ASSERT_NE(e.Release(), nullptr);
  ASSERT_EQ(e.Release(), nullptr);
}

/// \brief Test Error iterators over a chain of errors.
TEST(StructuredError_Error, Iterator) {
  const serror::Error chain =
      serror::ASN1Error::kInvalidFormat >>
      serror::CertificateError::kMalformed >>
      serror::OpenSSLClientConfigurationError::kCertificate >>
      serror::OpenSSLConfigurationError::kInvalid >>
      serror::APIError::kConfiguration;
  ASSERT_TRUE(chain);
  auto it = chain.begin();
  const auto end = chain.end();

  ASSERT_NE(it, end);

  ASSERT_EQ(*it, serror::APIError::kConfiguration);
  ++it;
  ASSERT_NE(it, end);

  ASSERT_EQ(*it, serror::OpenSSLConfigurationError::kInvalid);
  ++it;
  ASSERT_NE(it, end);

  ASSERT_EQ(*it, serror::OpenSSLClientConfigurationError::kCertificate);
  ++it;
  ASSERT_NE(it, end);

  ASSERT_EQ(*it, serror::CertificateError::kMalformed);
  ++it;
  ASSERT_NE(it, end);

  ASSERT_EQ(*it, serror::ASN1Error::kInvalidFormat);
  ++it;
  ASSERT_EQ(it, end);

  std::size_t i = 0;
  for (const auto &ec : chain) {
    for (std::size_t j = 0; j < i; ++j) {
      std::cout << '\t';
    }
    std::cout << " -~-~-~-> " << ec << "\r\n";
    ++i;
  }
  ASSERT_EQ(i, 5);
}

/// \brief Test empty/invalid/ok iterator.
TEST(StructuredError_Error, IteratorNonError) {
  const serror::Error e;
  auto it = e.begin();
  ASSERT_EQ(it, e.end());
}

/// \brief Test FreeChain
TEST(StructuredError_Error, FreeChain) {
  serror::Error chain = serror::ASN1Error::kInvalidFormat >>
                        serror::CertificateError::kMalformed >>
                        serror::OpenSSLClientConfigurationError::kCertificate >>
                        serror::OpenSSLConfigurationError::kInvalid >>
                        serror::APIError::kConfiguration;
  ASSERT_TRUE(chain);
  auto *ec = chain.Release();
  ASSERT_NE(ec, nullptr);
  FreeChain(ec);
  // The following assert can't be verified, because `ec` gets `delete`
  // therefore the allocator strategy may already rewrite something to the
  // chunk.
  // ASSERT_EQ(ec->details, nullptr);
}

/// \brief Test chaining with empty error.
TEST(StructuredError_Error, ChainWithEmptyError) {
  serror::Error e;
  e = e >> serror::ASN1Error::kInvalidFormat;
  ASSERT_TRUE(e);
  ASSERT_EQ(e, serror::ASN1Error::kInvalidFormat);
}
