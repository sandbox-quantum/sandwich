// Copyright 2022 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
