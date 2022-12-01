/**
 * \file
 * \brief Enum HandshakeState in namespace SandwichTunnel.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Enum HandshakeState. */
enum SandwichTunnelHandshakeState { 
  SANDWICH_TUNNEL_HANDSHAKESTATE_IN_PROGRESS = 0,
  SANDWICH_TUNNEL_HANDSHAKESTATE_DONE = 1,
  SANDWICH_TUNNEL_HANDSHAKESTATE_WANT_READ = 2,
  SANDWICH_TUNNEL_HANDSHAKESTATE_WANT_WRITE = 3,
  SANDWICH_TUNNEL_HANDSHAKESTATE_ERROR = 4,
};
typedef enum SandwichTunnelHandshakeState SandwichTunnelHandshakeState;

#ifdef __cplusplus
} // end extern "C"
#endif
