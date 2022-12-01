///
/// \file
/// \brief Factory for contexts, implementation.
///
/// \author thb-sb

#include "cc/context.h"
#include "cc/openssl/context.h"

namespace saq::sandwich {

auto Context::FromConfiguration(const ProtoConfiguration &config)
    -> ContextResult {
  if (!Protocol_IsValid(config.protocol()) ||
      (config.protocol() == proto::api::v1::Protocol::PROTO_UNSPECIFIED)) {
    return Error::kInvalidConfiguration;
  }
  if (!Implementation_IsValid(config.impl()) ||
      (config.impl() == proto::api::v1::Implementation::IMPL_UNSPECIFIED)) {
    return Error::kInvalidConfiguration;
  }

  switch (config.impl()) {
    case proto::api::v1::Implementation::IMPL_OPENSSL1_1_1:
    case proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS: {
      return openssl::Context::FromConfiguration(config);
    };
    default: {
      __builtin_unreachable();
    };
  }
}

} // end namespace saq::sandwich
