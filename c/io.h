/*
 * Copyright 2022 SandboxAQ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

///
/// \file
/// \brief Sandwich io::IO interface for generic C pointers.
///
/// \author thb-sb

#pragma once

#include <functional>
#include <utility>

#include "c/sandwich.h"
#include "c/tunnel_types.h"
#include "cc/io/io.h"
#include "cc/tunnel_types.h"

namespace saq::sandwich::c {

/// \brief io::IO class accepting C pointers as read and write handlers.
class CIO final : public saq::sandwich::io::IO {
 public:
  /// \brief A read function, in C.
  ///
  /// \param uarg User opaque argument, forwarded.
  /// \param buf Destination buffer.
  /// \param count Count of bytes to read.
  /// \param tunnel_state Tunnel state.
  /// \param[out] err An error code.
  ///
  /// When the read function returns -1, `err` contains the error code.
  ///
  /// \return Amount of bytes successfully read, or -1 if an error occurred.
  using ReadFunction = std::size_t (*)(void *uarg, void *buf, size_t count,
                                       enum SandwichTunnelState tunnel_state,
                                       IO::Error *);

  /// \brief A Write function, in C.
  ///
  /// \param buf Source buffer.
  /// \param count Count of bytes to write.
  /// \param tunnel_state Tunnel state.
  /// \param[out] err An error code.
  /// \param uarg User opaque argument, forwarded.
  ///
  /// When the write function returns -1, `err` contains the error code.
  ///
  /// \return Amount of bytes successfully written, or -1 if an error occurred.
  using WriteFunction = std::size_t (*)(void *uarg, const void *buf,
                                        size_t count,
                                        enum SandwichTunnelState tunnel_state,
                                        IO::Error *);

  /// \brief A Close function, in C.
  ///
  /// \param uarg User opaque argument, forwarded.
  using CloseFunction = void (*)(void *uarg);

  /// \brief Create an empty CIO object from a SandwichCIOSettings.
  ///
  /// \param settings Settings.
  ///
  /// \return A new CIO object.
  [[nodiscard]] static auto New(
      const struct ::SandwichCIOSettings &settings) noexcept
      -> std::unique_ptr<CIO>;

  /// \brief Copy constructor.
  CIO(const CIO &) noexcept = delete;

  /// \brief Move constructor.
  CIO(CIO &&) noexcept = default;

  /// \brief Copy assignment.
  auto operator=(const CIO &) noexcept -> CIO & = delete;

  /// \brief Move assignment.
  auto operator=(CIO &&) noexcept -> CIO & = default;

  /// \brief Destructor.
  ~CIO() noexcept override;

  [[nodiscard]] auto Write(std::span<const std::byte> buffer,
                           tunnel::State state) noexcept -> OpResult override;
  [[nodiscard]] auto Read(std::span<std::byte> buffer,
                          tunnel::State state) noexcept -> OpResult override;
  void Close() noexcept override;

  /// \brief Set the user opaque argument to forward to read, write and close.
  ///
  /// \param uarg User opaque argument.
  inline void SetUserArgument(void *uarg) noexcept { settings_.uarg = uarg; }

 private:
  /// \brief Constructor.
  ///
  /// \param settings Settings to use.
  inline CIO(const struct ::SandwichCIOSettings &settings) noexcept
      : settings_{settings} {};

  /// \brief Settings for Sandwich CIO.
  struct SandwichCIOSettings settings_ = {};
};

} // end namespace saq::sandwich::c
