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
/// \brief Frontend for contexts, implementation
///
/// \author thb-sb

#include "cc/context.h"

#include "c/sandwich.h"

#ifdef __cplusplus
extern "C" {
#endif

SANDWICH_API enum ::SandwichError sandwich_context_new(
    const void *src, size_t n, struct SandwichContext **ctx) {
  const std::span<const std::byte> msg(reinterpret_cast<const std::byte *>(src),
                                       n);
  auto res = saq::sandwich::Context::FromSerializedConfiguration(msg);
  if (res) {
    *ctx = reinterpret_cast<std::remove_pointer_t<decltype(ctx)>>(
        res.Get().release());
    return SANDWICH_ERROR_OK;
  }
  return static_cast<enum ::SandwichError>(res.GetError());
}

SANDWICH_API void sandwich_context_free(struct SandwichContext *ctx) {
  delete reinterpret_cast<saq::sandwich::Context *>(ctx);
}

#ifdef __cplusplus
} // end extern "C"
#endif
