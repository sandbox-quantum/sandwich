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
