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
/// \brief Sandwich C library, on top of the C++ library.
///
/// \author thb-sb

#pragma once

#include <sys/types.h>

#if (defined(__clang__) || (_GNUC__ >= 4))
#define SANDWICH_API __attribute__((visibility("default")))
#else
#define SANDWICH_API
#endif

#include "c/error_codes.h"
#include "c/ioerrors.h"
#include "c/tunnel_handshake_state.h"
#include "c/tunnel_record_errors.h"
#include "c/tunnel_state.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief An I/O object (PIMPL).
struct SandwichCIO;

/// \brief A Sandwich context (PIMPL).
struct SandwichContext;

/// \brief A Sandwich tunnel (PIMPL).
struct SandwichTunnel;

/// \brief An error code. Copy of error.h:ErrorCode.
struct SandwichError {
  /// \brief The encapsulated error.
  struct SandwichError *details;

  /// \brief The error kind. See error::ErrorKind enum.
  SandwichErrorKind kind;

  /// \brief The error code.
  int code;
};

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

/// \brief Close the I/O interface.
///
/// \param[in,out] uarg User opaque argument
typedef void(SandwichCIOCloseFunction)(void *uarg);
typedef SandwichCIOCloseFunction *SandwichCIOCloseFunctionPtr;

/// \brief Settings for a generic I/O interface.
///
/// This object is used to build a `saq::sandwich::io::CIO`.
struct SandwichCIOSettings {
  /// \brief The read function.
  SandwichCIOReadFunctionPtr read;

  /// \brief The write function.
  SandwichCIOWriteFunctionPtr write;

  /// \brief The close function.
  SandwichCIOCloseFunctionPtr close;

  /// \brief Opaque argument to forward to read, write and close.
  void *uarg;
};

/// \brief Free an error chain.
///
/// \param chain Error chain.
SANDWICH_API void sandwich_error_free(struct SandwichError *chain);

/// \brief Create an I/O interface.
///
/// \param[in] cioset Settings for the I/O interface.
/// \param[out] cio The new CIO object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *sandwich_io_new(
    const struct SandwichCIOSettings *cioset, struct SandwichCIO **cio);

/// \brief Free an I/O interface.
///
/// \param[in,out] cio I/O interface to free.
///
/// NULL for `cio` is allowed.
///
/// \return The I/O interface to free.
SANDWICH_API void sandwich_io_free(struct SandwichCIO *cio);

/// \brief Create a context from an encoded protobuf message.
///
/// \param[in] src Source buffer containing the encoded protobuf message.
/// \param n Size of the source buffer.
/// \param[out] ctx The new Sandwich context object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *sandwich_context_new(
    const void *src, size_t n, struct SandwichContext **ctx);

/// \brief Free a Sandwich context.
///
/// \param[in,out] ctx Context to free.
///
/// NULL for `cio` is allowed.
SANDWICH_API void sandwich_context_free(struct SandwichContext *ctx);

/// \brief Create a tunnel.
///
/// A tunnel is created from an I/O interface. The tunnel takes the ownership
/// of the I/O interface. Therefore, when the tunnel is destroyed with
/// `sandwich_tunnel_free`, the I/O interface is also destroyed.
/// `sandwich_tunnel_io_release` take the ownership of the I/O interface back
/// to the user.
///
/// \param[in] ctx Sandwich context used for setting up the tunnel.
/// \param[in,out] cio I/O interface to use for creating the tunnel.
/// \param[out] tun The new Sandwich tunnel object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *sandwich_tunnel_new(
    struct SandwichContext *ctx, struct SandwichCIO *cio,
    struct SandwichTunnel **tun);

/// \brief Perform the handshake.
///
/// \param[in,out] tun Tunnel.
///
/// \return The state of the handshake.
SANDWICH_API enum SandwichTunnelHandshakeState sandwich_tunnel_handshake(
    struct SandwichTunnel *tun);

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
SANDWICH_API enum SandwichTunnelRecordError sandwich_tunnel_read(
    struct SandwichTunnel *tun, void *dst, size_t n, size_t *r);

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
SANDWICH_API enum SandwichTunnelRecordError sandwich_tunnel_write(
    struct SandwichTunnel *tun, const void *src, size_t n, size_t *w);

/// \brief Close the tunnel.
///
/// \param[in,out] tun Tunnel to close.
SANDWICH_API void sandwich_tunnel_close(struct SandwichTunnel *tun);

/// \brief Get the state of the tunnel.
///
/// \param[in] tun Tunnel.
///
/// \return The state of the tunnel.
SANDWICH_API enum SandwichTunnelState sandwich_tunnel_state(
    const struct SandwichTunnel *tun);

/// \brief Release the I/O interface from the tunnel.
///
/// When the I/O interface is released, the tunnel can no longer be used.
///
/// \param[in,out] tun The Sandwich tunnel
///
/// \return The I/O interface, or NULL if the I/O interface has already been
/// released from the tunnel.
SANDWICH_API struct SandwichCIO *sandwich_tunnel_io_release(
    struct SandwichTunnel *tun);

/// \brief Free a Sandwich tunnel.
///
/// If the I/O interface is still owned by the tunnel, it will be freed too.
///
/// \param[in,out] tun Tunnel to free.
///
/// NULL for `tun` is allowed.
SANDWICH_API void sandwich_tunnel_free(struct SandwichTunnel *tun);

#ifdef __cplusplus
} // end extern "C"
#endif
