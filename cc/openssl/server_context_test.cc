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
/// \brief Unit tests for ServerContext
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
TEST(ServerContextTests, InvalidProtocolTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      &config));

  config.mutable_server()->clear_tls();

  auto res = saq::sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got good configuration";
  ASSERT_EQ(res.GetError(), saq::sandwich::Error::kInvalidConfiguration)
      << "Bad error code";
}

/// \brief Test with invalid KEM
TEST(ServerContextTests, InvalidKEMTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      &config));

  ASSERT_TRUE(TLSConfigurationAddKEM(&config, "Kyb3r1337"));

  auto res = saq::sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got good configuration";
  ASSERT_EQ(res.GetError(), saq::sandwich::Error::kInvalidKem)
      << "Bad error code";
}

/// \brief Test with no certificate or kems
TEST(ServerContextTests, NoCertNoKEMTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      &config));

  auto res = saq::sandwich::Context::FromConfiguration(config);
  ASSERT_TRUE(res) << "Expected good configuration, got bad configuration";
}

/// \brief Test with invalid certificate: invalid path
TEST(ServerContextTests, InvalidCertBadPathTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      &config));

  ASSERT_TRUE(TLSConfigurationSetCertificate(
      &config, "path/does/not/exist",
      sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_DER));
  auto res = saq::sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got good configuration";
  ASSERT_EQ(res.GetError(), saq::sandwich::Error::kInvalidCertificate)
      << "Bad error code";
}

/// \brief Test with invalid certificate: neither path or buffer
TEST(ServerContextTests, InvalidCertEmptyTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      &config));

  auto *cert = config.mutable_server()
                   ->mutable_tls()
                   ->mutable_certificate()
                   ->mutable_static_();

  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_DER);

  auto res = saq::sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got good configuration";
  ASSERT_EQ(res.GetError(), saq::sandwich::Error::kInvalidConfiguration)
      << "Bad error code";
}

/// \brief Test with invalid certificate: invalid encoding format
TEST(ServerContextTests, InvalidCertInvalidFormatTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      &config));

  auto *cert = config.mutable_server()
                   ->mutable_tls()
                   ->mutable_certificate()
                   ->mutable_static_();

  cert->mutable_data()->set_filename("testdata/cert.pem");
  cert->set_format(
      static_cast<saq::sandwich::proto::api::v1::ASN1EncodingFormat>(42));

  auto res = saq::sandwich::Context::FromConfiguration(config);
  ASSERT_FALSE(res) << "Expected bad configuration, got good configuration";
  ASSERT_EQ(res.GetError(), saq::sandwich::Error::kInvalidConfiguration)
      << "Bad error code";
}

/// \brief Test with a valid KEM
TEST(ServerContextTests, NoCertOneValidKEMTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      &config));

  ASSERT_TRUE(TLSConfigurationAddKEM(&config, "kyber1024"));

  auto res = saq::sandwich::Context::FromConfiguration(config);
  ASSERT_TRUE(res) << "Expected good configuration, got bad configuration";
}

/// \brief Test with a valid KEM and a valid certificate
TEST(ServerContextTests, ValidCertValidKEMTest) {
  sandwich_api::Configuration config;
  ASSERT_TRUE(NewTLSConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      &config));

  ASSERT_TRUE(TLSConfigurationAddKEM(&config, "kyber1024"));

  ASSERT_TRUE(TLSConfigurationSetCertificate(
      &config, "testdata/cert.pem",
      sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM));
  ASSERT_TRUE(TLSConfigurationSetPrivateKey(
      &config, "testdata/key.pem",
      sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM));

  auto res = saq::sandwich::Context::FromConfiguration(config);
  ASSERT_TRUE(res) << "Expected good configuration, got bad configuration";
}
