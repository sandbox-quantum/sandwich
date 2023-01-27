/*
 * Copyright 2023 SandboxAQ
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
/// \brief Error strings API specification.
///
/// \author thb-sb

#pragma once

#include <ostream>
#include <string_view>

#include "cc/error.h"
#include "cc/io/ioerrors.h"
#include "cc/tunnel_handshake_state.h"
#include "cc/tunnel_record_errors.h"
#include "cc/tunnel_state.h"

namespace saq::sandwich::error {

/// \brief Error strings for the kind and the code of error.
class ErrorString {
 public:
  /// \brief Default string for no error.
  static constexpr std::string_view kNoErrorString{"no error"};

  /// \brief Default string for unknown error kind.
  static constexpr std::string_view kUnknownErrorKindString{
      "unknown error kind"};

  /// \brief Default string for unknown error code.
  static constexpr std::string_view kUnknownErrorCodeString{
      "unknown error code"};

  /// \brief Create an empty error string.
  constexpr ErrorString() noexcept;

  /// \brief Create an error string from an Error.
  ///
  /// \param err Error.
  explicit ErrorString(const Error &err) noexcept;

  /// \brief Create an error string from an ErrorCode.
  ///
  /// \param ec Error code.
  explicit ErrorString(const ErrorCode *ec) noexcept;

  /// \brief Get the kind string.
  ///
  /// \return The kind string.
  [[nodiscard]] auto Kind() const noexcept -> const std::string_view &;

  /// \brief Get the code string.
  ///
  /// \return The code string.
  [[nodiscard]] auto Code() const noexcept -> const std::string_view &;

  /// \brief Dump the error string to an ostream.
  ///
  /// \param os Output stream.
  ///
  /// \return The output stream.
  auto operator<<(std::ostream &os) const noexcept -> std::ostream &;

 private:
  /// \brief Error string for the kind of error.
  std::string_view kind_{kUnknownErrorKindString};

  /// \brief Error string for the error code.
  std::string_view code_{kUnknownErrorCodeString};
};

/// \brief Display an ErrorString.
///
/// \param os Output stream.
/// \param es Error string to display.
///
/// \return The original output stream.
auto operator<<(std::ostream &os, const ErrorString &es) -> std::ostream &;

/// \brief Display an ErrorCode.
///
/// \param os Output stream.
/// \param es Error string to display.
///
/// \return The original output stream.
auto operator<<(std::ostream &os, const ErrorCode &ec) -> std::ostream &;

/// \brief Get the error string associated with an error enum code.
///
/// \param err Error code.
///
/// \return The error string.
auto GetStringError(const error::Error &err) -> ErrorString;

/// \brief Get the error string associated with a record error enum code.
///
/// \param err Error code.
///
/// \return The error string.
auto GetStringError(enum tunnel::RecordError err) -> std::string_view;

/// \brief Get the error string associated with an i/o error enum code.
///
/// \param err Error code.
///
/// \return The error string.
auto GetStringError(enum io::IOError err) -> std::string_view;

/// \brief Get the error string associated with a state enum code.
///
/// \param err State code.
///
/// \return The error string.
auto GetStringError(enum tunnel::State err) -> std::string_view;

/// \brief Get the error string associated with an handshake state enum code.
///
/// \param err Handshake state code.
///
/// \return The error string.
auto GetStringError(enum tunnel::HandshakeState err) -> std::string_view;

} // end namespace saq::sandwich::error
