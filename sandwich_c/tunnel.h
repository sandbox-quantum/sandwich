// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Sandwich Tunnel API.

#pragma once

#include <sys/types.h>

#include "sandwich_c/export.h"
#include "sandwich_c/io.h"
#include "sandwich_c/tunnel_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief A Sandwich tunnel context.
struct SandwichTunnelContext;

/// \brief A serialized `Configuration` message.
struct SandwichTunnelContextConfigurationSerialized {
  /// \brief Buffer containing the serialized `Configuration` message.
  const void *src;

  /// \brief Size of `src`.
  size_t n;
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

/// \brief A Sandwich tunnel.
struct SandwichTunnel;

/// \brief An IO callback triggered when the state of the tunnel changes.
///
/// It is guaranteed that the state of the tunnel will not change between two
/// calls to this callback.
///
/// \param[in,out] uarg User opaque argument.
/// \param tunnel_state The new state of the tunnel.
typedef void(SandwichTunnelIOSetStateFunction)(
    void *uarg, enum SandwichTunnelState tunnel_state);
typedef SandwichTunnelIOSetStateFunction *SandwichTunnelIOSetStateFunctionPtr;

/// \brief An IO specific to tunnels.
struct SandwichTunnelIO {
  /// \brief The base IO object.
  struct SandwichIO base;

  /// \brief The callback used to indicate when the state of the tunnel changes.
  ///
  /// It is guaranteed that the state of the tunnel will not change between two
  /// calls to this callback.
  ///
  /// `NULL` is a valid value.
  SandwichTunnelIOSetStateFunctionPtr set_state;
};

/// \brief Create a context from an encoded protobuf message.
///
/// \param sw Top-level Sandwich context.
/// \param configuration Serialized configuration.
/// \param[out] ctx The new Sandwich context object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *sandwich_tunnel_context_new(
    const struct SandwichContext *sw,
    struct SandwichTunnelContextConfigurationSerialized configuration,
    struct SandwichTunnelContext **ctx);

/// \brief Free a Sandwich tunnel context.
///
/// \param[in,out] ctx Context to free.
///
/// NULL for `ctx` is allowed.
SANDWICH_API void
sandwich_tunnel_context_free(struct SandwichTunnelContext *ctx);

/// \brief Create a tunnel.
///
/// A tunnel is created from an IO interface. `SandwichTunnelIO` are
/// used to create an IO interface that forwards calls to the `read`, and
/// `write` of `SandwichTunnelIO`.
/// The state of the tunnel is exposed to the IO interface through the
/// ::SandwichTunnelIO->set_state function.
///
/// Since the implementation of `sandwich_tunnel_new` makes a copy of
/// `SandwichTunnelIO`, the caller does not need to keep `io` in memory.
/// In other words, Sandwich does not take the ownership of `io`.
///
/// \param[in] ctx Sandwich context used for setting up the tunnel.
/// \param[in] io I/O interface to use to create the I/O interface.
/// \param[in] configuration Additional configuration the connection is subject
/// to.
///            A null pointer is undefined behavior.
/// \param[out] tun The new Sandwich tunnel object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *
sandwich_tunnel_new(struct SandwichTunnelContext *ctx,
                    const struct SandwichTunnelIO *io,
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

#ifdef __cplusplus
} // end extern "C"
#endif
