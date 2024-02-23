

# File error.h

[**File List**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**error.h**](error_8h.md)

[Go to the documentation of this file](error_8h.md)

```C++

// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only


#pragma once

#include "sandwich_c/error_codes.h"
#include "sandwich_c/export.h"

#ifdef __cplusplus
extern "C" {
#endif

struct SandwichError {
  struct SandwichError *details;

  const char *msg;

  SandwichErrorKind kind;

  int code;
};

SANDWICH_API void sandwich_error_free(struct SandwichError *chain);

SANDWICH_API char *
sandwich_error_stack_str_new(const struct SandwichError *chain);

SANDWICH_API void sandwich_error_stack_str_free(const char *err_str);

#ifdef __cplusplus
} // end extern "C"
#endif

```

