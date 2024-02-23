

# File tunnel.h

[**File List**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**tunnel.h**](tunnel_8h.md)

[Go to the documentation of this file](tunnel_8h.md)

```C++

// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only


#pragma once

#include <sys/types.h>

#include "sandwich_c/export.h"
#include "sandwich_c/io.h"
#include "sandwich_c/tunnel_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct SandwichTunnelContext;

struct SandwichTunnelContextConfigurationSerialized {
  const void *src;

  size_t n;
};

struct SandwichTunnelConfigurationSerialized {
  const void *src;

  size_t n;
};

extern struct SandwichTunnelConfigurationSerialized
    SandwichTunnelConfigurationVerifierEmpty;

struct SandwichTunnel;

typedef void(SandwichTunnelIOSetStateFunction)(
    void *uarg, enum SandwichTunnelState tunnel_state);
typedef SandwichTunnelIOSetStateFunction *SandwichTunnelIOSetStateFunctionPtr;

struct SandwichTunnelIO {
  struct SandwichIO base;

  SandwichTunnelIOSetStateFunctionPtr set_state;
};

SANDWICH_API struct SandwichError *sandwich_tunnel_context_new(
    const struct SandwichContext *sw,
    struct SandwichTunnelContextConfigurationSerialized configuration,
    struct SandwichTunnelContext **ctx);

SANDWICH_API void
sandwich_tunnel_context_free(struct SandwichTunnelContext *ctx);

SANDWICH_API struct SandwichError *
sandwich_tunnel_new(struct SandwichTunnelContext *ctx,
                    const struct SandwichTunnelIO *io,
                    struct SandwichTunnelConfigurationSerialized configuration,
                    struct SandwichTunnel **tun);

SANDWICH_API struct SandwichError *
sandwich_tunnel_handshake(struct SandwichTunnel *tun,
                          enum SandwichTunnelHandshakeState *state);

SANDWICH_API enum SandwichTunnelRecordError
sandwich_tunnel_read(struct SandwichTunnel *tun, void *dst, size_t n,
                     size_t *r);

SANDWICH_API enum SandwichTunnelRecordError
sandwich_tunnel_write(struct SandwichTunnel *tun, const void *src, size_t n,
                      size_t *w);

SANDWICH_API void sandwich_tunnel_close(struct SandwichTunnel *tun);

SANDWICH_API enum SandwichTunnelState
sandwich_tunnel_state(const struct SandwichTunnel *tun);

SANDWICH_API void sandwich_tunnel_free(struct SandwichTunnel *tun);

SANDWICH_API struct SandwichTunnelIO
sandwich_owned_io_to_tunnel_io(const struct SandwichIOOwned *owned_io);

#ifdef __cplusplus
} // end extern "C"
#endif

```

