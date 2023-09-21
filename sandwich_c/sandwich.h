// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Sandwich C library, on top of the Rust implementation.
///
/// \author thb-sb

#pragma once

#include <sys/types.h>

#if (defined(__clang__) || (_GNUC__ >= 4))
#define SANDWICH_API __attribute__((visibility("default")))
#else
#define SANDWICH_API
#endif

#include "sandwich_c/error_codes.h"
#include "sandwich_c/ioerrors.h"
#include "sandwich_c/tunnel_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief A Sandwich context (PIMPL).
struct SandwichTunnelContext;

/// \brief A Sandwich tunnel (PIMPL).
struct SandwichTunnel;

/// \brief An error code. Copy of error.h:ErrorCode.
struct SandwichError {
  /// \brief The encapsulated error.
  struct SandwichError *details;

  /// \brief An optional error string
  const char *msg;

  /// \brief The error kind. See error::ErrorKind enum.
  SandwichErrorKind kind;

  /// \brief The error code.
  int code;
};

/// \brief A serialized `TunnelConfiguration` message.
struct SandwichTunnelConfigurationSerialized {
  /// \brief Buffer containing the serialized `TunnelConfiguration` message.
  const void *src;

  /// \brief Size of `src`.
  size_t n;
};

/// \brief A tunnel configuration containing an empty Tunnel Verifier.
extern struct SandwichTunnelConfigurationSerialized
    SandwichTunnelConfigurationVerifierEmpty;

/// \brief Read function for the I/O interface.
///
/// \param[in,out] uarg User opaque argument.
/// \param[out] buf Destination buffer.
/// \param count Amount of bytes to read.
/// \param tunnel_state Current state of the tunnel.
/// \param[out] err Error, if any.
///
/// \return The amount of bytes successfully read, or 0.
typedef size_t(SandwichCIOReadFunction)(void *uarg, void *buf, size_t count,
                                        enum SandwichTunnelState tunnel_state,
                                        enum SandwichIOError *err);
typedef SandwichCIOReadFunction *SandwichCIOReadFunctionPtr;

/// \brief Write function for the I/O interface.
///
/// \param[in,out] uarg User opaque argument.
/// \param[out] buf Source buffer.
/// \param count Amount of bytes to write.
/// \param tunnel_state Current state of the tunnel.
/// \param[out] err Error, if any.
///
/// \return The amount of bytes successfully written, or 0.
typedef size_t(SandwichCIOWriteFunction)(void *uarg, const void *buf,
                                         size_t count,
                                         enum SandwichTunnelState tunnel_state,
                                         enum SandwichIOError *err);
typedef SandwichCIOWriteFunction *SandwichCIOWriteFunctionPtr;

/// \brief Settings for a generic I/O interface.
///
/// This object is used to build a `saq::sandwich::io::CIO`.
struct SandwichCIOSettings {
  /// \brief The read function.
  SandwichCIOReadFunctionPtr read;

  /// \brief The write function.
  SandwichCIOWriteFunctionPtr write;

  /// \brief Opaque argument to forward to read, and write.
  void *uarg;
};

typedef void(SandwichOwnedIoFreeFunction)(struct SandwichCIOSettings *cio);
typedef SandwichOwnedIoFreeFunction *SandwichOwnedIoFreeFunctionPtr;

/// \brief An IO owned by the Sandwich Library.
///
/// ::SandwichCIOOwned objects owns the underlying `io->uarg` object pointer,
/// and provides a `freeptr` function that is responsible for destroying that
/// object. ::SandwichCIOOwned must be freed by calling the
/// ::sandwich_io_owned_free function. This is what is returned from
/// sandwich_io_*_new functions.
struct SandwichCIOOwned {
  // \brief the io which is owned by Sandwich.
  struct SandwichCIOSettings *io;

  // \brief the function used to free the owned io.
  SandwichOwnedIoFreeFunctionPtr freeptr;
};

/// \brief Free an error chain.
///
/// \param chain Error chain.
SANDWICH_API void sandwich_error_free(struct SandwichError *chain);

/// \brief Create an error stack string from a SandwichError chain.
///
/// \param chain Error chain.
///
/// \return A NUL terminated string describing the SandwichError chain
SANDWICH_API char *
sandwich_error_stack_str_new(const struct SandwichError *chain);

/// \brief Free a an error string (generated from sandwich_error_stack_str_new)
///
/// \param err_str Pointer to error string to free.
///
/// NULL for err_str is allowed.
SANDWICH_API void sandwich_error_stack_str_free(const char *err_str);

/// \brief Create a context from an encoded protobuf message.
///
/// \param[in] src Source buffer containing the encoded protobuf message.
/// \param n Size of the source buffer.
/// \param[out] ctx The new Sandwich context object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *
sandwich_tunnel_context_new(const void *src, size_t n,
                            struct SandwichTunnelContext **ctx);

/// \brief Free a Sandwich context.
///
/// \param[in,out] ctx Context to free.
///
/// NULL for `cio` is allowed.
SANDWICH_API void
sandwich_tunnel_context_free(struct SandwichTunnelContext *ctx);

/// \brief Validate a configuration provided as an encoded protobuf message.
///
/// \param[in] src Source buffer containing the encoded protobuf message.
/// \param n Size of the source buffer.
///
/// \return NULL if no error occurred, else a chain of errors.
SANDWICH_API struct SandwichError *
sandwich_tunnel_config_validate(const void *src, size_t n);

/// \brief Create a tunnel.
///
/// A tunnel is created from an I/O interface. `SandwichCIOSettings` are
/// used to create an I/O interface that forwards calls to the `read`, and
/// `write` of `SandwichCIOSettings`.
///
/// Since the implementation of `sandwich_tunnel_new` makes a copy of
/// `SandwichCIOSettings`, the caller does not need to keep `cio` in memory.
/// In other words, Sandwich does not take the ownership of `cio`.
///
/// \param[in] ctx Sandwich context used for setting up the tunnel.
/// \param[in] cio I/O interface settings to use to create the I/O interface.
/// \param[in] configuration Additional configuration the connection is subject
/// to.
///            A null pointer is undefined behavior.
/// \param[out] tun The new Sandwich tunnel object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *
sandwich_tunnel_new(struct SandwichTunnelContext *ctx,
                    const struct SandwichCIOSettings *cio,
                    struct SandwichTunnelConfigurationSerialized configuration,
                    struct SandwichTunnel **tun);

/// \brief Perform the handshake.
///
/// \param[in,out] tun Tunnel.
/// \param[out] state The state of the tunnel
///
/// \return Null if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *
sandwich_tunnel_handshake(struct SandwichTunnel *tun,
                          enum SandwichTunnelHandshakeState *state);

/// \brief Read some bytes from the record plane of the tunnel.
///
/// \param[in,out] tun Tunnel..
/// \param[out] dst Destination buffer.
/// \param n Amount of bytes to read.
/// \param[out] r Amount of bytes successfully read.
///
/// NULL for `r` is allowed.
///
/// \return An error code.
SANDWICH_API enum SandwichTunnelRecordError
sandwich_tunnel_read(struct SandwichTunnel *tun, void *dst, size_t n,
                     size_t *r);

/// \brief Write some bytes to the record plane of the tunnel.
///
/// \param[in,out] tun Tunnel.
/// \param[in] src Source buffer.
/// \param n Amount of bytes to read.
/// \param[out] w Amount of bytes successfully written.
///
/// NULL for `w` is allowed.
///
/// \return An error code.
SANDWICH_API enum SandwichTunnelRecordError
sandwich_tunnel_write(struct SandwichTunnel *tun, const void *src, size_t n,
                      size_t *w);

/// \brief Close the tunnel.
///
/// \param[in,out] tun Tunnel to close.
SANDWICH_API void sandwich_tunnel_close(struct SandwichTunnel *tun);

/// \brief Get the state of the tunnel.
///
/// \param[in] tun Tunnel.
///
/// \return The state of the tunnel.
SANDWICH_API enum SandwichTunnelState
sandwich_tunnel_state(const struct SandwichTunnel *tun);

/// \brief Free a Sandwich tunnel.
///
/// If the I/O interface is still owned by the tunnel, it will be freed too.
///
/// \param[in,out] tun Tunnel to free.
///
/// NULL for `tun` is allowed.
SANDWICH_API void sandwich_tunnel_free(struct SandwichTunnel *tun);

/// \brief Creates a TCP based IO object to be used for a client tunnel
///
/// \param[in] hostname the hostname of the target server.
/// \param[in] port the port number of the target server.
/// \param[in] async indicates whether sockets should be non-blocking or not.
/// \param[out] ownedIO the created TCP based sandwich owned IO object.
///
/// \return IOERROR_OK if the operation was a success, otherwise returns the
///         error that occured.
SANDWICH_API enum SandwichIOError
sandwich_io_client_tcp_new(const char *hostname, const uint16_t port,
                           bool async, struct SandwichCIOOwned **ownedIO);

/// \brief Creates an IO object that wrapps a UNIX socket
///
/// \param[in] fd the file descriptor of the unix socket.
/// \param[out] ownedIO the created UNIX socket sandwich owned IO object. The
/// caller is responsible for freeing that object with ::sandwich_io_owned_free.
///
/// \return IOERROR_OK if the operation was a success, otherwise returns the
///         error that occured.
SANDWICH_API enum SandwichIOError
sandwich_io_socket_wrap_new(int fd, struct SandwichCIOOwned **ownedIO);

/// \brief Frees a SandwichCIOOwned object created by one of the
///        sandwich_io_*_new() functions.
SANDWICH_API void sandwich_io_owned_free(struct SandwichCIOOwned *ownedIO);

#ifdef __cplusplus
} // end extern "C"
#endif
