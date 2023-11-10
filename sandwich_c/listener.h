// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Sandwich C library, on top of the Rust implementation.

#pragma once

#include <sys/types.h>

#include "sandwich_c/export.h"
#include "sandwich_c/io.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief A Sandwich listener (PIMPL).
struct SandwichListener;

/// \brief Creates a a new Listener object.
///
/// \param[in] src a serialized `ListenerConfiguration` protobuf message.
/// \param[in] n the length of src.
/// \param[out] out points to the newly created listener.
///
/// \return Error, if any.
SANDWICH_API struct SandwichError *
sandwich_listener_new(const void *src, size_t n, struct SandwichListener **out);

/// \brief Causes the Listener to start listening for connections.
///
/// \param[in] listener The listener object that should start listening
///            for new connections.
///
/// \return IOERROR_OK if the operation was a success, otherwise returns the
///         error that occurred.
SANDWICH_API enum SandwichIOError
sandwich_listener_listen(struct SandwichListener *listener);

/// \brief Prompts the Listener to start accepting connections.
///
/// \param[in] listener the listener which should start accepting connections.
/// \param[out] ownedIO the newly created OwnedIO struct containing the IO
/// object to use with
///	    a tunnel. Null if an error occurs.
///
/// \return IOERROR_OK if the operation was a success, otherwise returns
/// 	    the error that occurred.
SANDWICH_API enum SandwichIOError
sandwich_listener_accept(struct SandwichListener *listener,
                         struct SandwichIOOwned **ownedIO);

/// \brief Closes the listener to new connections.
///
/// \param[in] listener the listener which should close.
SANDWICH_API void sandwich_listener_close(struct SandwichListener *listener);

/// \brief Frees the given listener.
///
/// \param[in] listener the listener which should start accepting connections.
SANDWICH_API void sandwich_listener_free(struct SandwichListener *listener);

#ifdef __cplusplus
} // end extern "C"
#endif
