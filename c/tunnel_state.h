/**
 * \file
 * \brief Enum State in namespace SandwichTunnel.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Enum State. */
enum SandwichTunnelState { 
  SANDWICH_TUNNEL_STATE_NOT_CONNECTED = 0,
  SANDWICH_TUNNEL_STATE_CONNECTION_IN_PROGRESS = 1,
  SANDWICH_TUNNEL_STATE_HANDSHAKE_IN_PROGRESS = 2,
  SANDWICH_TUNNEL_STATE_HANDSHAKE_DONE = 3,
  SANDWICH_TUNNEL_STATE_BEING_SHUTDOWN = 4,
  SANDWICH_TUNNEL_STATE_DISCONNECTED = 5,
  SANDWICH_TUNNEL_STATE_ERROR = 6,
};
typedef enum SandwichTunnelState SandwichTunnelState;

#ifdef __cplusplus
} // end extern "C"
#endif
