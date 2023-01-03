// Copyright 2022 SandboxAQ
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
/// \brief Unit tests for ClientContext
///
/// \author thb-sb

#include <cassert>
#include <iostream>

#include "cc/context.h"
#include "cc/result.h"
#include "cc/tests_utils.h"
#include "proto/sandwich.pb.h"

namespace {

/// \brief Create a configuration.
///
/// \param mode Mode.
/// \param impl Implementation.
/// \param proto Protocol.
///
/// \return The configuration.
auto NewConfiguration(
    const saq::sandwich::proto::Mode mode,
    const saq::sandwich::proto::api::v1::Implementation impl,
    const saq::sandwich::proto::api::v1::Protocol proto)
    -> saq::sandwich::proto::api::v1::Configuration {
  saq::sandwich::proto::api::v1::Configuration config{};

  config.set_protocol(proto);
  config.set_impl(impl);

  if (mode == saq::sandwich::proto::Mode::MODE_CLIENT) {
    config.mutable_client()->mutable_tls()->mutable_common_options();
  } else if (mode == saq::sandwich::proto::Mode::MODE_SERVER) {
    config.mutable_server()->mutable_tls()->mutable_common_options();
  }

  return config;
}

/// \brief Test with invalid protocol.
///
/// This test fails.
void TestWithInvalidProtocolNOK() {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  config.set_protocol(
      saq::sandwich::proto::api::v1::Protocol::PROTO_UNSPECIFIED);

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == false);
  sandwich_assert(res.GetError() ==
                  saq::sandwich::Error::kInvalidConfiguration);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief Test with invalid KEM
///
/// This test fails.
void TestWithInvalidKemNOK() {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  config.mutable_client()->mutable_tls()->mutable_common_options()->add_kem(
      "Kyb3r1337");

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == false);
  sandwich_assert(res.GetError() == saq::sandwich::Error::kInvalidKem);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief Test with no certificate or kems
///
/// This test succeeds.
void TestWithNoCertNoKemsOK() {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == true);
  auto ctx = std::move(res.Get());
  sandwich_assert(ctx != nullptr);
  sandwich_assert(ctx->Implementation() == config.impl());
  sandwich_assert(ctx->Protocol() == config.protocol());

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief Test with invalid certificate: invalid path
///
/// This test fails.
void TestWithInvalidCertBadPathNOK() {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  auto *cert = config.mutable_client()
                   ->mutable_tls()
                   ->add_trusted_certificates()
                   ->mutable_static_();

  cert->mutable_data()->set_filename("path/does/not/exists");
  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_DER);

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == false);
  sandwich_assert(res.GetError() ==
                  saq::sandwich::Error::kInvalidCertificate);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief Test with invalid certificate: neither path or buffer
///
/// This test fails.
void TestWithInvalidCertEmptyNOK() {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  auto *cert = config.mutable_client()
                   ->mutable_tls()
                   ->add_trusted_certificates()
                   ->mutable_static_();

  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_DER);

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == false);
  sandwich_assert(res.GetError() ==
                  saq::sandwich::Error::kInvalidConfiguration);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief Test with invalid certificate: invalid encoding format
///
/// This test fails.
void TestWithInvalidCertInvalidFormatNOK() {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  auto *cert = config.mutable_client()
                   ->mutable_tls()
                   ->add_trusted_certificates()
                   ->mutable_static_();

  cert->mutable_data()->set_filename("testdata/cert.pem");
  cert->set_format(
      static_cast<saq::sandwich::proto::api::v1::ASN1EncodingFormat>(42));

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == false);
  sandwich_assert(res.GetError() ==
                  saq::sandwich::Error::kInvalidConfiguration);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief Test with a valid KEM
///
/// This test succeeds.
void TestWithNoCertOneValidKemOK() {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  config.mutable_client()->mutable_tls()->mutable_common_options()->add_kem(
      "kyber1024");

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == true);
  auto ctx = std::move(res.Get());
  sandwich_assert(ctx != nullptr);
  sandwich_assert(ctx->Implementation() == config.impl());
  sandwich_assert(ctx->Protocol() == config.protocol());

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief Test with a valid KEM and a valid certificate
///
/// This test succeeds.
void TestWithValidCertValidKemOK() {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  config.mutable_client()->mutable_tls()->mutable_common_options()->add_kem(
      "kyber1024");

  auto *cert = config.mutable_client()
                   ->mutable_tls()
                   ->add_trusted_certificates()
                   ->mutable_static_();
  cert->mutable_data()->set_filename("testdata/cert.pem");
  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_PEM);

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == true);
  auto ctx = std::move(res.Get());
  sandwich_assert(ctx != nullptr);
  sandwich_assert(ctx->Implementation() == config.impl());
  sandwich_assert(ctx->Protocol() == config.protocol());

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

} // end anonymous namespace

auto main() -> int {
  TestWithInvalidProtocolNOK();
  TestWithInvalidKemNOK();
  TestWithInvalidCertBadPathNOK();
  TestWithInvalidCertEmptyNOK();
  TestWithInvalidCertInvalidFormatNOK();

  TestWithNoCertNoKemsOK();
  TestWithNoCertOneValidKemOK();
  TestWithValidCertValidKemOK();
  return 0;
}
