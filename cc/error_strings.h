///
/// \file
/// \brief Error strings API specification.
///
/// \author thb-sb

#pragma once

#include <string_view>

#include "cc/errors.h"
#include "cc/io/ioerrors.h"
#include "cc/tunnel_handshake_state.h"
#include "cc/tunnel_record_errors.h"
#include "cc/tunnel_state.h"

namespace saq::sandwich {

/// \brief Get the error string associated with an error enum code.
///
/// \param err Error code.
///
/// \return The error string.
auto GetStringError(enum Error err) -> std::string_view;

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

} // end namespace saq::sandwich
