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
/// \brief Factory for contexts, implementation.
///
/// \author thb-sb

#include "cc/context.h"
#include "cc/openssl/context.h"

namespace saq::sandwich {

auto Context::FromConfiguration(const ProtoConfiguration &config)
    -> ContextResult {
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
