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
