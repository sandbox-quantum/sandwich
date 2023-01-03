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
