// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief I/O abstraction for Sandwich.

#pragma once

#include <sys/types.h>

#include "sandwich_c/export.h"
#include "sandwich_c/ioerrors.h"
#include "sandwich_c/tunnel_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief Read function for the I/O interface.
///
/// \param[in,out] uarg User opaque argument.
/// \param[out] buf Destination buffer.
/// \param count Amount of bytes to read.
/// \param tunnel_state Current state of the tunnel.
/// \param[out] err Error, if any.
///
/// \return The amount of bytes successfully read, or 0.
typedef size_t(SandwichIOReadFunction)(void *uarg, void *buf, size_t count,
                                       enum SandwichTunnelState tunnel_state,
                                       enum SandwichIOError *err);
typedef SandwichIOReadFunction *SandwichIOReadFunctionPtr;

/// \brief Write function for the I/O interface.
///
/// \param[in,out] uarg User opaque argument.
/// \param[out] buf Source buffer.
/// \param count Amount of bytes to write.
/// \param tunnel_state Current state of the tunnel.
/// \param[out] err Error, if any.
///
/// \return The amount of bytes successfully written, or 0.
typedef size_t(SandwichIOWriteFunction)(void *uarg, const void *buf,
                                        size_t count,
                                        enum SandwichTunnelState tunnel_state,
                                        enum SandwichIOError *err);
typedef SandwichIOWriteFunction *SandwichIOWriteFunctionPtr;

/// \brief Flush function for the I/O interface.
///
/// \param[in,out] uarg User opaque argument.
///
/// \return IOERROR_OK if success, else an IO error.
typedef enum SandwichIOError(SandwichIOFlushFunction)(void *uarg);
typedef SandwichIOFlushFunction *SandwichIOFlushFunctionPtr;

/// \brief A generic I/O interface.
struct SandwichIO {
  /// \brief The read function.
  SandwichIOReadFunctionPtr read;

  /// \brief The write function.
  SandwichIOWriteFunctionPtr write;

  /// \brief The flush function.
  ///
  /// `NULL` is a valid value for flush.
  SandwichIOFlushFunctionPtr flush;

  /// \brief Opaque argument to forward to read, write and flush.
  void *uarg;
};

/// \brief A destructor function for owned I/O interface.
typedef void(SandwichOwnedIOFreeFunction)(struct SandwichIO *io);
typedef SandwichOwnedIOFreeFunction *SandwichOwnedIOFreeFunctionPtr;

/// \brief An IO owned by the Sandwich Library.
///
/// ::SandwichIOOwned objects owns the underlying `io->uarg` object pointer,
/// and provides a `freeptr` function that is responsible for destroying that
/// object. ::SandwichIOOwned must be freed by calling the
/// ::sandwich_io_owned_free function. This is what is returned from
/// sandwich_io_*_new functions.
struct SandwichIOOwned {
  // \brief the io which is owned by Sandwich.
  struct SandwichIO *io;

  // \brief the function used to free the owned io.
  SandwichOwnedIOFreeFunctionPtr freeptr;
};

/// \brief Creates a TCP based IO object to be used for a client tunnel
///
/// \param[in] hostname the hostname of the target server.
/// \param[in] port the port number of the target server.
/// \param[in] async indicates whether sockets should be non-blocking or not.
/// \param[out] ownedIO the created TCP based sandwich owned IO object.
///
/// \return IOERROR_OK if the operation was a success, otherwise returns the
///         error that occurred.
SANDWICH_API enum SandwichIOError
sandwich_io_client_tcp_new(const char *hostname, uint16_t port, bool async,
                           struct SandwichIOOwned **ownedIO);

/// \brief Creates an IO object that wraps a UNIX socket
///
/// \param[in] fd the file descriptor of the unix socket.
/// \param[out] ownedIO the created UNIX socket sandwich owned IO object. The
/// caller is responsible for freeing that object with ::sandwich_io_owned_free.
///
/// \return IOERROR_OK if the operation was a success, otherwise returns the
///         error that occurred.
SANDWICH_API enum SandwichIOError
sandwich_io_socket_wrap_new(int fd, struct SandwichIOOwned **ownedIO);

/// \brief Frees a SandwichIOOwned object created by one of the
///        sandwich_io_*_new() functions.
SANDWICH_API void sandwich_io_owned_free(struct SandwichIOOwned *ownedIO);

#ifdef __cplusplus
} // end extern "C"
#endif
