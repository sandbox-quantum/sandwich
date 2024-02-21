// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Turbo transport, on top of the Rust implementation.
///
/// \author jgoertzen-sb

#pragma once

#include "sandwich_c/export.h"
#include "sandwich_c/io.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief Creates a Turbo based IO object to be used for a client tunnel.
///
/// \param[in] udp_hostname the hostname of the target UDP server.
/// \param[in] udp_port the port number of the target  UDP server.
/// \param[in] tcp_hostname the hostname of the target TCP server.
/// \param[in] tcp_port the port number of the target TCP server.
/// \param[in] async indicates whether sockets should be non-blocking or not.
/// \param[out] ownedIO the created TCP based sandwich owned IO object.
///
/// \return IOERROR_OK if the operation was a success, otherwise returns the
///         error that occurred.
SANDWICH_API enum SandwichIOError
sandwich_io_client_turbo_new(const char *udp_hostname, const uint16_t udp_port,
			   const char *tcp_hostname, const uint16_t tcp_port,
                           bool is_blocking, struct SandwichIOOwned **ownedIO);

#ifdef __cplusplus
} // end extern "C"
#endif
