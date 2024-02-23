

# File lib.h

[**File List**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**lib.h**](lib_8h.md)

[Go to the documentation of this file](lib_8h.md)

```C++

// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "sandwich_c/export.h"

#ifdef __cplusplus
extern "C" {
#endif


struct SandwichContext;

SANDWICH_API struct SandwichContext *sandwich_lib_context_new(void);

SANDWICH_API void sandwich_lib_context_free(struct SandwichContext *sw);

#ifdef __cplusplus
} // end extern "C"
#endif

```

