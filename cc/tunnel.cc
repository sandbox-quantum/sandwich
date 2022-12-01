///
/// \file
/// \brief Tunnel implementation.
///
/// \author thb-sb

#include "cc/tunnel.h"

#include <cassert>

#include "cc/io/io.h"

namespace saq::sandwich {

auto Tunnel::GetError() const noexcept -> io::IO::Error {
  return io_->GetError();
}

auto Tunnel::SetState(State state) noexcept -> State {
  return (state_ = state);
}

auto Tunnel::ReleaseIO() -> std::unique_ptr<io::IO> {
  return std::move(io_);
}

Tunnel::Tunnel(std::unique_ptr<io::IO> ioint) noexcept
    : io_{std::move(ioint)} {}

Tunnel::~Tunnel() = default;

} // end namespace saq::sandwich
