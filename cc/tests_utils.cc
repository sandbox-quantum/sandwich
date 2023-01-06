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

#include "cc/error_strings.h"
#include "cc/io/socket.h"

auto NewConfiguration(const sandwich_proto::Mode mode,
                      const sandwich_api::Implementation impl,
                      const sandwich_api::Protocol proto,
                      sandwich_api::Configuration *config)
    -> testing::AssertionResult {
  if (!sandwich_proto::Mode_IsValid(mode)) {
    return testing::AssertionFailure() << mode << " isn't a valid mode";
  }
  if (!sandwich_api::Implementation_IsValid(impl)) {
    return testing::AssertionFailure()
           << impl << " isn't a valid implementation";
  }
  if (!sandwich_api::Protocol_IsValid(proto)) {
    return testing::AssertionFailure() << proto << " isn't a valid protocol";
  }
  if (config == nullptr) {
    return testing::AssertionFailure() << "`config` must not be null";
  }

  config->set_protocol(proto);
  config->set_impl(impl);

  if (proto == sandwich_api::Protocol::PROTO_TLS_13) {
    if (mode == sandwich_proto::Mode::MODE_CLIENT) {
      config->mutable_client()->mutable_tls()->mutable_common_options();
    } else if (mode == sandwich_proto::Mode::MODE_SERVER) {
      config->mutable_server()->mutable_tls()->mutable_common_options();
    } else {
      return testing::AssertionFailure() << "Unreachable code";
    }
  }

  return testing::AssertionSuccess();
}

auto TLSConfigurationSetCertificate(
    sandwich_api::Configuration *config, const std::string_view &certpath,
    const sandwich_api::ASN1EncodingFormat certfmt)
    -> testing::AssertionResult {
  if (config == nullptr) {
    return testing::AssertionFailure()
           << "Expected non-null pointer for `config`";
  }
  if (certpath.empty()) {
    return testing::AssertionFailure()
           << "Expected non-empty string for `certpath`";
  }
  if (!sandwich_api::ASN1EncodingFormat_IsValid(certfmt)) {
    return testing::AssertionFailure()
           << certfmt << " isn't a valid ASN.1 format";
  }

  sandwich_api::ASN1DataSource *certsrc{nullptr};
  if (config->has_client()) {
    if (!config->mutable_client()->has_tls()) {
      return testing::AssertionFailure()
             << "client must have a TLS configuration";
    }
    auto *cert{
        config->mutable_client()->mutable_tls()->add_trusted_certificates()};
    if (cert == nullptr) {
      return testing::AssertionFailure()
             << "`add_trusted_certificates` returned null pointer";
    }
    certsrc = cert->mutable_static_();
  } else if (config->has_server()) {
    if (!config->mutable_server()->has_tls()) {
      return testing::AssertionFailure()
             << "server must have a TLS configuration";
    }
    auto *cert{config->mutable_server()->mutable_tls()->mutable_certificate()};
    if (cert == nullptr) {
      return testing::AssertionFailure()
             << "`add_trusted_certificates` returned null pointer";
    }
    certsrc = cert->mutable_static_();
  } else {
    return testing::AssertionFailure()
           << "`config` must have either the client or the server "
              "configuration, and cannot be empty";
  }
  if (certsrc == nullptr) {
    return testing::AssertionFailure()
           << "Certificate source is a null pointer";
  }
  certsrc->mutable_data()->set_filename(std::string{certpath});
  certsrc->set_format(certfmt);

  return testing::AssertionSuccess();
}

auto TLSConfigurationSetPrivateKey(
    sandwich_api::Configuration *config, const std::string_view &keypath,
    const sandwich_api::ASN1EncodingFormat keyfmt) -> testing::AssertionResult {
  if (config == nullptr) {
    return testing::AssertionFailure()
           << "Expected non-null pointer for `config`";
  }
  if (keypath.empty()) {
    return testing::AssertionFailure()
           << "Expected non-empty string for `keypath`";
  }
  if (!sandwich_api::ASN1EncodingFormat_IsValid(keyfmt)) {
    return testing::AssertionFailure()
           << keyfmt << " isn't a valid ASN.1 format";
  }

  if (!config->has_server()) {
    return testing::AssertionFailure()
           << "`config` must have a server configuration";
  }
  if (!config->mutable_server()->has_tls()) {
    return testing::AssertionFailure()
           << "server configuration must have a TLS configuration";
  }

  auto *pkey{config->mutable_server()->mutable_tls()->mutable_private_key()};
  if (pkey == nullptr) {
    return testing::AssertionFailure()
           << "`mutable_private_key` returned a null pointer";
  }
  auto *pkeysrc{pkey->mutable_static_()};
  if (pkey == nullptr) {
    return testing::AssertionFailure()
           << "`mutable_static_` returned a null pointer";
  }
  pkeysrc->mutable_data()->set_filename(std::string{keypath});
  pkeysrc->set_format(keyfmt);

  return testing::AssertionSuccess();
}

auto TLSConfigurationAddKEM(sandwich_api::Configuration *config,
                            const std::string_view &kem)
    -> testing::AssertionResult {
  if (config == nullptr) {
    return testing::AssertionFailure()
           << "Expected non-null pointer for `config`";
  }
  if (kem.empty()) {
    return testing::AssertionFailure() << "Expected non-empty string for `kem`";
  }

  if (config->has_client()) {
    if (!config->mutable_client()->has_tls()) {
      return testing::AssertionFailure()
             << "client must have a TLS configuration";
    }
    if (!config->mutable_client()->mutable_tls()->has_common_options()) {
      return testing::AssertionFailure()
             << "client must have common TLS options";
    }
    config->mutable_client()->mutable_tls()->mutable_common_options()->add_kem(
        std::string{kem});
  } else if (config->has_server()) {
    if (!config->mutable_server()->has_tls()) {
      return testing::AssertionFailure()
             << "server must have a TLS configuration";
    }
    if (!config->mutable_server()->mutable_tls()->has_common_options()) {
      return testing::AssertionFailure()
             << "client must have common TLS options";
    }
    config->mutable_server()->mutable_tls()->mutable_common_options()->add_kem(
        std::string{kem});
  } else {
    return testing::AssertionFailure()
           << "`config` must contain either the client or the server "
              "configuration, and cannot be empty";
  }

  return testing::AssertionSuccess();
}

auto TLSConfigurationAddKEMs(sandwich_api::Configuration *config,
                             const std::span<const std::string_view> &kems)
    -> testing::AssertionResult {
  for (const auto &k : kems) {
    if (auto ares = TLSConfigurationAddKEM(config, k); !ares) {
      return testing::AssertionFailure()
             << "Failed to add kem '" << k << "': " << ares;
    }
  }

  return testing::AssertionSuccess();
}

auto CreateContext(const sandwich_api::Configuration &config,
                   std::unique_ptr<sandwich::Context> *context)
    -> testing::AssertionResult {
  if (context == nullptr) {
    return testing::AssertionFailure() << "`context` must not be null";
  }

  auto res{saq::sandwich::Context::FromConfiguration(config)};
  if (!res) {
    return testing::AssertionFailure()
           << "`Context::FromConfiguration` returned an error: "
           << sandwich::GetStringError(res.GetError());
  }
  *context = std::move(res.Get());
  if ((*context)->Implementation() != config.impl()) {
    return testing::AssertionFailure()
           << "Expected impl " << config.impl() << ", got "
           << (*context)->Implementation();
  }
  if ((*context)->Protocol() != config.protocol()) {
    return testing::AssertionFailure()
           << "Expected protocol " << config.protocol() << ", got "
           << (*context)->Protocol();
  }
  return testing::AssertionSuccess();
}

auto CreateTunnel(std::unique_ptr<sandwich::Context> *context,
                  std::unique_ptr<sandwich::io::IO> ioint,
                  std::unique_ptr<sandwich::Tunnel> *tun)
    -> testing::AssertionResult {
  if (tun == nullptr) {
    return testing::AssertionFailure() << "`tun` must not be null";
  }

  auto res{(*context)->NewTunnel(std::move(ioint))};
  if (!res) {
    return testing::AssertionFailure()
           << "Failed to create the tunnel: "
           << sandwich::GetStringError(res.GetError());
  }
  *tun = std::move(res.Get());

  return testing::AssertionSuccess();
}

auto CreateTLSClientContext(const std::string_view &certpath,
                            const sandwich_api::ASN1EncodingFormat certfmt,
                            const std::string_view &kem,
                            std::unique_ptr<sandwich::Context> *context)
    -> testing::AssertionResult {
  if (context == nullptr) {
    return testing::AssertionFailure() << "`context` must not be null";
  }

  auto ares{testing::AssertionFailure() << "Undefined value returned"};
  sandwich_api::Configuration config;
  if (ares =
          NewConfiguration(sandwich_proto::Mode::MODE_CLIENT,
                           sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS,
                           sandwich_api::Protocol::PROTO_TLS_13, &config);
      !ares) {
    return ares;
  }

  if (ares = TLSConfigurationSetCertificate(&config, certpath, certfmt);
      !ares) {
    return ares;
  }
  if (ares = TLSConfigurationAddKEM(&config, kem); !ares) {
    return ares;
  }
  return CreateContext(config, context);
}

auto CreateTLSServerContext(const std::string_view &certpath,
                            const sandwich_api::ASN1EncodingFormat certfmt,
                            const std::string_view &keypath,
                            const sandwich_api::ASN1EncodingFormat keyfmt,
                            const std::string_view &kem,
                            std::unique_ptr<sandwich::Context> *context)
    -> testing::AssertionResult {
  if (context == nullptr) {
    return testing::AssertionFailure() << "`context` must not be null";
  }

  auto ares{testing::AssertionFailure() << "Undefined value returned"};

  sandwich_api::Configuration config;
  if (ares =
          NewConfiguration(sandwich_proto::Mode::MODE_SERVER,
                           sandwich_api::Implementation::IMPL_OPENSSL1_1_1_OQS,
                           sandwich_api::Protocol::PROTO_TLS_13, &config);
      !ares) {
    return ares;
  }

  if (ares = TLSConfigurationSetCertificate(&config, certpath, certfmt);
      !ares) {
    return ares;
  }
  if (ares = TLSConfigurationSetPrivateKey(&config, keypath, keyfmt); !ares) {
    return ares;
  }
  if (ares = TLSConfigurationAddKEM(&config, kem); !ares) {
    return ares;
  }
  return CreateContext(config, context);
}

auto CreateSocketIOPair(const std::array<int, 2> &fds, IOPair *pair)
    -> testing::AssertionResult {
  auto res{sandwich::io::Socket::FromFd(fds[0])};
  if (!res) {
    return testing::AssertionFailure()
           << "Failed to create the client socket: "
           << sandwich::GetStringError(res.GetError());
  }
  pair->client = std::move(res.Get());

  res = sandwich::io::Socket::FromFd(fds[1]);
  if (!res) {
    return testing::AssertionFailure()
           << "Failed to create the client socket: "
           << sandwich::GetStringError(res.GetError());
  }
  pair->server = std::move(res.Get());

  return testing::AssertionSuccess();
}
