

# File tunnel\_types.h

[**File List**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**tunnel\_types.h**](tunnel__types_8h.md)

[Go to the documentation of this file](tunnel__types_8h.md)

```C++

// Copyright 2023 SandboxAQ
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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


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

enum SandwichTunnelHandshakeState { 
  SANDWICH_TUNNEL_HANDSHAKESTATE_IN_PROGRESS = 0,
  SANDWICH_TUNNEL_HANDSHAKESTATE_DONE = 1,
  SANDWICH_TUNNEL_HANDSHAKESTATE_WANT_READ = 2,
  SANDWICH_TUNNEL_HANDSHAKESTATE_WANT_WRITE = 3,
  SANDWICH_TUNNEL_HANDSHAKESTATE_ERROR = 4,
};
typedef enum SandwichTunnelHandshakeState SandwichTunnelHandshakeState;

enum SandwichTunnelRecordError { 
  SANDWICH_TUNNEL_RECORDERROR_OK = 0,
  SANDWICH_TUNNEL_RECORDERROR_WANT_READ = 1,
  SANDWICH_TUNNEL_RECORDERROR_WANT_WRITE = 2,
  SANDWICH_TUNNEL_RECORDERROR_BEING_SHUTDOWN = 3,
  SANDWICH_TUNNEL_RECORDERROR_CLOSED = 4,
  SANDWICH_TUNNEL_RECORDERROR_TOO_BIG = 5,
  SANDWICH_TUNNEL_RECORDERROR_UNKNOWN = 6,
};
typedef enum SandwichTunnelRecordError SandwichTunnelRecordError;


#ifdef __cplusplus
} // end extern "C"
#endif

```

