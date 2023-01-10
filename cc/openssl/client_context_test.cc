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
/// \brief Unit tests for ClientContext
///
/// \author thb-sb

#include <cassert>
#include <iostream>

#include "gtest/gtest.h"

#include "cc/context.h"
#include "cc/result.h"
#include "cc/tests_utils.h"
#include "proto/sandwich.pb.h"

/// \brief Test with invalid protocol.
TEST(ClientContextTests, InvalidProtocolTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      sandwich_proto::Mode::MODE_CLIENT,
      sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS, &config));

  config.mutable_client()->clear_tls();

  auto res = sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got a good configuration";
  ASSERT_EQ(res.GetError(), sandwich::Error::kInvalidConfiguration)
      << "Bad error code";
}

/// \brief Test with invalid KEM
TEST(ClientContextTests, InvalidKEMTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      sandwich_proto::Mode::MODE_CLIENT,
      sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS, &config));

  ASSERT_TRUE(TLSConfigurationAddKEM(&config, "Kyb3r1337"));

  auto res = sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got a good configuration";
  ASSERT_EQ(res.GetError(), sandwich::Error::kInvalidKem) << "Bad error code";
}

/// \brief Test with no certificate or kems
TEST(ClientContextTests, NoCertNoKEMTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      sandwich_proto::Mode::MODE_CLIENT,
      sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS, &config));

  auto res = sandwich::Context::FromConfiguration(config);
  ASSERT_TRUE(res) << "Expected good configuration";
}

/// \brief Test with invalid certificate: invalid path
TEST(ClientContextTests, InvalidCertBadPathTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      sandwich_proto::Mode::MODE_CLIENT,
      sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS, &config));

  ASSERT_TRUE(TLSConfigurationSetCertificate(
      &config, "path/does/not/exist",
      sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_DER));

  auto res = sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got good configuration";
  ASSERT_EQ(res.GetError(), sandwich::Error::kInvalidCertificate)
      << "Bad error code";
}

/// \brief Test with invalid certificate: neither path or buffer
TEST(ClientContextTests, InvalidCertEmptyTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      sandwich_proto::Mode::MODE_CLIENT,
      sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS, &config));

  auto *cert = config.mutable_client()
                   ->mutable_tls()
                   ->add_trusted_certificates()
                   ->mutable_static_();

  cert->set_format(sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);

  auto res = sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got good configuration";
  ASSERT_EQ(res.GetError(), sandwich::Error::kInvalidConfiguration)
      << "Bad error code";
}

/// \brief Test with invalid certificate: invalid encoding format
TEST(ClientContextTests, ValidCertInvalidFormatTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      sandwich_proto::Mode::MODE_CLIENT,
      sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS, &config));

  auto *cert = config.mutable_client()
                   ->mutable_tls()
                   ->add_trusted_certificates()
                   ->mutable_static_();

  cert->mutable_data()->set_filename("testdata/cert.pem");
  cert->set_format(static_cast<sandwich_api::ASN1EncodingFormat>(42));

  auto res = sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got good configuration";
  ASSERT_EQ(res.GetError(), sandwich::Error::kInvalidConfiguration)
      << "Bad error code";
}

/// \brief Test with a valid KEM
TEST(ClientContextTests, NoCertOneValidKEMTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      sandwich_proto::Mode::MODE_CLIENT,
      sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS, &config));

  ASSERT_TRUE(TLSConfigurationAddKEM(&config, "kyber1024"));

  auto res = sandwich::Context::FromConfiguration(config);
  ASSERT_TRUE(res) << "Expected good configuration, got bad configuration";
}

/// \brief Test with a valid KEM and a valid certificate
TEST(ClientContextTests, ValidCertValidKEMTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      sandwich_proto::Mode::MODE_CLIENT,
      sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS, &config));

  ASSERT_TRUE(TLSConfigurationAddKEM(&config, "kyber1024"));
  ASSERT_TRUE(TLSConfigurationSetCertificate(
      &config, "testdata/cert.pem",
      sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM));

  auto res = sandwich::Context::FromConfiguration(config);
  ASSERT_TRUE(res) << "Expected good configuration, got bad configuration";
}
