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
/// \brief Functions for unit tests, implementation.
///
/// \author thb-sb

#include "cc/tests_utils.h"

#include "cc/io/socket.h"

auto NewConfiguration(const sandwich_proto::Mode mode,
                      const sandwich_api::Implementation impl,
                      const sandwich_api::Protocol proto)
    -> sandwich_api::Configuration {
  sandwich_api::Configuration config{};

  sandwich_assert(sandwich_proto::Mode_IsValid(mode));
  sandwich_assert(sandwich_api::Implementation_IsValid(impl));
  sandwich_assert(sandwich_api::Protocol_IsValid(proto));

  config.set_protocol(proto);
  config.set_impl(impl);

  if (proto == sandwich_api::Protocol::PROTO_TLS_13) {
    if (mode == sandwich_proto::Mode::MODE_CLIENT) {
      config.mutable_client()->mutable_tls()->mutable_common_options();
    } else if (mode == sandwich_proto::Mode::MODE_SERVER) {
      config.mutable_server()->mutable_tls()->mutable_common_options();
    } else {
      __builtin_unreachable();
    }
  }

  return config;
}

void TLSConfigurationSetCertificate(
    sandwich_api::Configuration *config, const std::string_view &certpath,
    const sandwich_api::ASN1EncodingFormat certfmt) {
  sandwich_assert(config != nullptr);
  sandwich_assert(!certpath.empty());
  sandwich_assert(sandwich_api::ASN1EncodingFormat_IsValid(certfmt));

  sandwich_api::ASN1DataSource *certsrc{nullptr};
  if (config->has_client()) {
    sandwich_assert(config->mutable_client()->has_tls());
    auto *cert{
        config->mutable_client()->mutable_tls()->add_trusted_certificates()};
    sandwich_assert(cert != nullptr);
    certsrc = cert->mutable_static_();
  } else if (config->has_server()) {
    sandwich_assert(config->mutable_server()->has_tls());
    auto *cert{config->mutable_server()->mutable_tls()->mutable_certificate()};
    sandwich_assert(cert != nullptr);
    certsrc = cert->mutable_static_();
  } else {
    sandwich_assert(false);
  }
  sandwich_assert(certsrc != nullptr);
  certsrc->mutable_data()->set_filename(std::string{certpath});
  certsrc->set_format(certfmt);
}

void TLSConfigurationSetPrivateKey(
    sandwich_api::Configuration *config, const std::string_view &keypath,
    const sandwich_api::ASN1EncodingFormat keyfmt) {
  sandwich_assert(config != nullptr);
  sandwich_assert(!keypath.empty());
  sandwich_assert(sandwich_api::ASN1EncodingFormat_IsValid(keyfmt));

  sandwich_assert(config->has_server());

  sandwich_assert(config->mutable_server()->has_tls());
  auto *pkey{config->mutable_server()->mutable_tls()->mutable_private_key()};
  sandwich_assert(pkey != nullptr);
  auto *pkeysrc{pkey->mutable_static_()};
  sandwich_assert(pkeysrc != nullptr);
  pkeysrc->mutable_data()->set_filename(std::string{keypath});
  pkeysrc->set_format(keyfmt);
}

void TLSConfigurationAddKEM(sandwich_api::Configuration *config,
                            const std::string_view &kem) {
  sandwich_assert(config != nullptr);
  sandwich_assert(!kem.empty());

  if (config->has_client()) {
    sandwich_assert(config->mutable_client()->has_tls());
    sandwich_assert(
        config->mutable_client()->mutable_tls()->has_common_options());
    config->mutable_client()->mutable_tls()->mutable_common_options()->add_kem(
        std::string{kem});
  } else if (config->has_server()) {
    sandwich_assert(config->mutable_server()->has_tls());
    sandwich_assert(
        config->mutable_server()->mutable_tls()->has_common_options());
    config->mutable_server()->mutable_tls()->mutable_common_options()->add_kem(
        std::string{kem});
  } else {
    sandwich_assert(false);
  }
}

void TLSConfigurationAddKEMs(sandwich_api::Configuration *config,
                             const std::span<const std::string_view> &kems) {
  for (const auto &k : kems) {
    TLSConfigurationAddKEM(config, k);
  }
}

auto CreateContext(const sandwich_api::Configuration &config)
    -> std::unique_ptr<sandwich::Context> {
  auto res{saq::sandwich::Context::FromConfiguration(config)};
  sandwich_assert(res == true);
  auto ctx{std::move(res.Get())};
  sandwich_assert(ctx->Implementation() == config.impl());
  sandwich_assert(ctx->Protocol() == config.protocol());
  return ctx;
}

auto CreateTunnel(std::unique_ptr<sandwich::Context> *context,
                  std::unique_ptr<sandwich::io::IO> ioint)
    -> std::unique_ptr<sandwich::Tunnel> {
  auto res{(*context)->NewTunnel(std::move(ioint))};
  sandwich_assert(res == true);
  return std::move(res.Get());
}

auto CreateTLSClientContext(const std::string_view &certpath,
                            const sandwich_api::ASN1EncodingFormat certfmt,
                            const std::string_view &kem)
    -> std::unique_ptr<sandwich::Context> {
  auto config{
      NewConfiguration(sandwich_proto::Mode::MODE_CLIENT,
                       sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS,
                       sandwich_api::Protocol::PROTO_TLS_13)};

  TLSConfigurationSetCertificate(&config, certpath, certfmt);
  TLSConfigurationAddKEM(&config, kem);
  return CreateContext(config);
}

auto CreateTLSServerContext(const std::string_view &certpath,
                            const sandwich_api::ASN1EncodingFormat certfmt,
                            const std::string_view &keypath,
                            const sandwich_api::ASN1EncodingFormat keyfmt,
                            const std::string_view &kem)
    -> std::unique_ptr<sandwich::Context> {
  auto config{
      NewConfiguration(sandwich_proto::Mode::MODE_SERVER,
                       sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS,
                       sandwich_api::Protocol::PROTO_TLS_13)};

  TLSConfigurationSetCertificate(&config, certpath, certfmt);
  TLSConfigurationSetPrivateKey(&config, keypath, keyfmt);
  TLSConfigurationAddKEM(&config, kem);
  return CreateContext(config);
}

auto CreateSocketIOPair(const std::array<int, 2> &fds) -> IOPair {
  IOPair pair;

  auto res{sandwich::io::Socket::FromFd(fds[0])};
  sandwich_assert(res != false);
  pair.client = std::move(res.Get());

  res = sandwich::io::Socket::FromFd(fds[1]);
  sandwich_assert(res != false);
  pair.server = std::move(res.Get());

  return pair;
}
