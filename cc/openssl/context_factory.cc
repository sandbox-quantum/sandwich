///
/// \file
/// \brief Factory for OpenSSL contexts, implementation.
///
/// \author thb-sb

#include "cc/openssl/client.h"
#include "cc/openssl/context.h"
#include "cc/openssl/server.h"

#include "proto/api/v1/configuration.pb.h"

namespace saq::sandwich::openssl {

namespace {

/// \brief Implementation(s) supported by this file.
///
/// \note We don't use a std::set because there is no constexpr constructor.
constexpr std::array<proto::api::v1::Implementation, 2>
    kSupportedImplementations = {
        proto::api::v1::Implementation::IMPL_OPENSSL1_1_1,
        proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
};

/// \brief Protocol(s) supported by this file.
///
/// \note We don't use a std::set because there is no constexpr constructor.
constexpr std::array<proto::api::v1::Protocol, 1> kSupportedProtocols = {
    proto::api::v1::Protocol::PROTO_TLS_13,
};

} // end anonymous namespace

auto Context::FromConfiguration(const ProtoConfiguration &config)
    -> ContextResult {
  if (std::find(kSupportedImplementations.begin(),
                kSupportedImplementations.end(),
                config.impl()) == kSupportedImplementations.end()) {
    return Error::kUnsupportedImplementation;
  }
  if (std::find(kSupportedProtocols.begin(), kSupportedProtocols.end(),
                config.protocol()) == kSupportedProtocols.end()) {
    return Error::kUnsupportedProtocol;
  }

  switch (config.opts_case()) {
    case proto::api::v1::Configuration::OptsCase::kClient: {
      return ClientContext::FromConfiguration(config);
    }
    case proto::api::v1::Configuration::OptsCase::kServer: {
      return ServerContext::FromConfiguration(config);
    }
    default: {
      return Error::kInvalidConfiguration;
    }
  }
}

} // end namespace saq::sandwich::openssl
