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
/// \brief Tunnel specification.
///
/// \author thb-sb

#pragma once

#include <span>

#include "cc/errors.h"
#include "cc/exports.h"
#include "cc/io/io.h"
#include "cc/result.h"
#include "cc/tunnel_handshake_state.h"
#include "cc/tunnel_record_errors.h"
#include "cc/tunnel_state.h"

namespace saq::sandwich {

/// \brief A Sandwich tunnel.
///
/// A tunnel is responsible for establishing the secure connection to
/// an endpoint.
/// To do that, it needs an I/O interface, which is an abstraction of all I/O
/// operations.
/// It also needs a context.
class SANDWICH_CC_API Tunnel {
public:
  /// \brief A result, wrapping a Tunnel or an error.
 using TunnelResult = Result<std::unique_ptr<Tunnel>, Error>;

 /// \brief Alias to saq::sandwich::tunnel::State.
 using State = saq::sandwich::tunnel::State;

 /// \brief Alias to saq::sandwich::tunnel::HandshakeState.
 using HandshakeState = saq::sandwich::tunnel::HandshakeState;

 /// \brief Alias to saq::sandwich::tunnel::RecordError.
 using RecordError = saq::sandwich::tunnel::RecordError;

 /// \brief A result from a record plane operation (`Read` or `Write`).
 class RecordResult : public Result<std::size_t, RecordError> {
  public:
   [[nodiscard]] inline auto WouldBlock() const noexcept -> bool {
     if (*this) {
       return false;
     }
     const auto err = GetError();
     return (static_cast<int>(err) &
             (static_cast<int>(RecordError::kWantRead) |
              static_cast<int>(RecordError::kWantWrite))) != 0;
   }
 };

  /// \brief Returns the current state of the tunnel.
  ///
  /// \return The current state of the tunnel.
  [[nodiscard]] inline auto GetState() const noexcept -> State {
    return state_;
  }

  /// \brief Returns the underlying I/O object.
  ///
  /// \return The underlying I/O object.
  [[nodiscard]] inline auto GetIO() noexcept -> io::IO & { return *io_; }

  /// \brief Returns the underlying I/O object.
  ///
  /// \return The underlying I/O object.
  [[nodiscard]] inline auto GetIO() const noexcept -> const io::IO & {
    return *io_;
  }

  /// \brief Returns the last recorded error.
  ///
  /// \return The last recorded error.
  [[nodiscard]] auto GetError() const noexcept -> io::IO::Error;

  /// \brief Connects to the endpoint.
  ///
  /// This method perform the I/O connection. It does not begin the handshake.
  ///
  /// \return A result tranfer.
  //[[nodiscard]] virtual auto Connect() -> io::IO::OpResult = 0;

  /// \brief Performs the handshake.
  ///
  /// \return the Handshake state.
  [[nodiscard]] virtual auto Handshake() -> HandshakeState = 0;

  /// \brief Close the tunnel.
  ///
  /// This routine changes the state of the tunnel to `kBeingShutdown`
  /// or `kDisconnected`, depending on the implementation.
  ///
  /// The new state of the tunnel is returned by this function.
  /// If `kBeingShutdown` is returned, the user may want to call this routine
  /// again, to make sure the tunnel is definitely closed.
  ///
  /// \warning The method does not close the underlying I/O object.
  /// To do so, the user must retrieve it, by calling `GetIO` or `ReleaseIO`.
  ///
  /// \return The current state of the tunnel.
  virtual auto Close() -> State = 0;

  /// \brief Read data from the tunnel.
  ///
  /// \param[out] buffer Buffer where to write read bytes.
  ///
  /// \note The state of the tunnel must be `kHandshakeDone`, otherwise it is
  ///       undefined behavior.
  ///
  /// \return An I/O result.
  [[nodiscard]] virtual auto Read(std::span<std::byte> buffer)
      -> RecordResult = 0;

  /// \brief Write data to the tunnel.
  ///
  /// \param[in] buffer Buffer to send.
  ///
  /// \note The state of the tunnel must be `kHandshakeDone`, otherwise it is
  ///       undefined behavior.
  ///
  /// \return An I/O result.
  [[nodiscard]] virtual auto Write(std::span<const std::byte> buffer)
      -> RecordResult = 0;

  /// \brief Releases the I/O interface from the tunnel.
  ///
  /// Get the ownership of the I/O interface back.
  ///
  /// \return The I/O interface.
  [[nodiscard]] auto ReleaseIO() -> std::unique_ptr<io::IO>;

  /// \brief Copy constructor, disallowed.
  Tunnel(const Tunnel &) noexcept = delete;

  /// \brief Move constructor.
  Tunnel(Tunnel &&) noexcept = default;

  /// \brief Copy assignment, disallowed.
  auto operator=(const Tunnel &) noexcept -> Tunnel & = delete;

  /// \brief Move assignment.
  auto operator=(Tunnel &&) noexcept -> Tunnel & = default;

  /// \brief Destructor.
  virtual ~Tunnel();

 protected:
  /// \brief Sets the current state.
  ///
  /// \param state The state to set.
  ///
  /// \return The new state.
  auto SetState(State state) noexcept -> State;

  /// \brief Constructor, from an I/O interface.
  ///
  /// \param[in] ioint IO object to use.
  explicit Tunnel(std::unique_ptr<io::IO> ioint) noexcept;

 private:
  /// \brief The underlying I/O object.
  std::unique_ptr<io::IO> io_;

  /// \brief Current state.
  State state_ = State::kNotConnected;
};

} // end namespace saq::sandwich
