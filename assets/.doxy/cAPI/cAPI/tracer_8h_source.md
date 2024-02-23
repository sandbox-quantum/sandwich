

# File tracer.h

[**File List**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**tracer.h**](tracer_8h.md)

[Go to the documentation of this file](tracer_8h.md)

```C++

// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only


#pragma once

#include <sys/types.h>

#include "sandwich_c/export.h"
#include "sandwich_c/tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

SANDWICH_API void sandwich_tunnel_add_tracer(struct SandwichTunnel *tun, const char *context_cstr, int fd);

#ifdef __cplusplus
} // end extern "C"
#endif

```

