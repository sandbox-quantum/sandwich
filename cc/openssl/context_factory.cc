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

} // end anonymous namespace

auto Context::FromConfiguration(const ProtoConfiguration &config)
    -> ContextResult {
  if (std::find(kSupportedImplementations.begin(),
                kSupportedImplementations.end(),
                config.impl()) == kSupportedImplementations.end()) {
    return error::OpenSSLConfigurationError::kUnsupportedImplementation;
  }

  std::optional<ContextResult> res = std::nullopt;
  switch (config.opts_case()) {
    case proto::api::v1::Configuration::OptsCase::kClient: {
      res = ClientContext::FromConfiguration(config);
    } break;
    case proto::api::v1::Configuration::OptsCase::kServer: {
      res = ServerContext::FromConfiguration(config);
    } break;
    default: {
      return error::OpenSSLConfigurationError::kInvalidCase;
    }
  }

  if (!*res) {
    return res->GetError() >> error::OpenSSLConfigurationError::kInvalid;
  }
  return std::move(*res);
}

} // end namespace saq::sandwich::openssl
