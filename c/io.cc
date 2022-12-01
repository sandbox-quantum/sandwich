///
/// \file
/// \brief Sandwich io::IO interface for generic C pointers, implementation.
///
/// \author thb-sb

#include "c/io.h"

#include <cassert>
#include <memory>

namespace saq::sandwich::c {

auto CIO::New(const struct ::SandwichCIOSettings &settings) noexcept
    -> std::unique_ptr<CIO> {
  assert(settings.read != nullptr);
  assert(settings.write != nullptr);
  assert(settings.close != nullptr);
  return std::unique_ptr<CIO>(new CIO(settings));
}

CIO::~CIO() noexcept = default;

auto CIO::Read(std::span<std::byte> buffer, const tunnel::State state) noexcept
    -> OpResult {
  Error err = Error::kUnknown;
  const auto amount =
      settings_.read(settings_.uarg, buffer.data(), buffer.size(),
                     static_cast<enum ::SandwichTunnelState>(state),
                     reinterpret_cast<enum ::SandwichIOError *>(&err));
  SetError(err);
  return {.count = amount, .err = err};
}

auto CIO::Write(std::span<const std::byte> buffer,
                const tunnel::State state) noexcept -> OpResult {
  assert(settings_.write != nullptr);
  Error err = Error::kUnknown;
  const auto amount =
      settings_.write(settings_.uarg, buffer.data(), buffer.size(),
                      static_cast<enum ::SandwichTunnelState>(state),
                      reinterpret_cast<enum ::SandwichIOError *>(&err));
  SetError(err);
  return {.count = amount, .err = err};
}

void CIO::Close() noexcept {
  settings_.close(settings_.uarg);
}

} // end namespace saq::sandwich::c

#ifdef __cplusplus
extern "C" {
#endif

SANDWICH_API enum ::SandwichError sandwich_io_new(
    const struct SandwichCIOSettings *cioset, struct SandwichCIO **cio) {
  saq::sandwich::c::CIO *cc = nullptr;
  if (auto c = saq::sandwich::c::CIO::New(*cioset); c != nullptr) {
    cc = c.release();
  } else {
    return SANDWICH_ERROR_MEMORY;
  }

  *cio = reinterpret_cast<std::remove_pointer_t<decltype(cio)>>(cc);
  return SANDWICH_ERROR_OK;
}

SANDWICH_API void sandwich_io_free(struct SandwichCIO *cio) {
  delete reinterpret_cast<saq::sandwich::c::CIO *>(cio);
}

#ifdef __cplusplus
} // end extern "C"
#endif
