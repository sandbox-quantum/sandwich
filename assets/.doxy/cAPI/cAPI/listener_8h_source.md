

# File listener.h

[**File List**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**listener.h**](listener_8h.md)

[Go to the documentation of this file](listener_8h.md)

```C++

// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only


#pragma once

#include <sys/types.h>

#include "sandwich_c/export.h"
#include "sandwich_c/io.h"

#ifdef __cplusplus
extern "C" {
#endif

struct SandwichListener;

SANDWICH_API struct SandwichError *
sandwich_listener_new(const void *src, size_t n, struct SandwichListener **out);

SANDWICH_API enum SandwichIOError
sandwich_listener_listen(struct SandwichListener *listener);

SANDWICH_API enum SandwichIOError
sandwich_listener_accept(struct SandwichListener *listener,
                         struct SandwichIOOwned **ownedIO);

SANDWICH_API void sandwich_listener_close(struct SandwichListener *listener);

SANDWICH_API void sandwich_listener_free(struct SandwichListener *listener);

#ifdef __cplusplus
} // end extern "C"
#endif

```

