

# File io.h

[**File List**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**io.h**](io_8h.md)

[Go to the documentation of this file](io_8h.md)

```C++

// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only


#pragma once

#include <sys/types.h>

#include "sandwich_c/export.h"
#include "sandwich_c/ioerrors.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef size_t(SandwichIOReadFunction)(void *uarg, void *buf, size_t count,
                                       enum SandwichIOError *err);
typedef SandwichIOReadFunction *SandwichIOReadFunctionPtr;

typedef size_t(SandwichIOWriteFunction)(void *uarg, const void *buf,
                                        size_t count,
                                        enum SandwichIOError *err);
typedef SandwichIOWriteFunction *SandwichIOWriteFunctionPtr;

typedef enum SandwichIOError(SandwichIOFlushFunction)(void *uarg);
typedef SandwichIOFlushFunction *SandwichIOFlushFunctionPtr;

struct SandwichIO {
  SandwichIOReadFunctionPtr read;

  SandwichIOWriteFunctionPtr write;

  SandwichIOFlushFunctionPtr flush;

  void *uarg;
};

typedef void(SandwichOwnedIOFreeFunction)(struct SandwichIO *io);
typedef SandwichOwnedIOFreeFunction *SandwichOwnedIOFreeFunctionPtr;

struct SandwichIOOwned {
  struct SandwichIO *io;

  SandwichOwnedIOFreeFunctionPtr freeptr;
};

SANDWICH_API enum SandwichIOError
sandwich_io_client_tcp_new(const char *hostname, uint16_t port, bool async,
                           struct SandwichIOOwned **ownedIO);

SANDWICH_API enum SandwichIOError
sandwich_io_socket_wrap_new(int fd, struct SandwichIOOwned **ownedIO);

SANDWICH_API void sandwich_io_owned_free(struct SandwichIOOwned *ownedIO);

#ifdef __cplusplus
} // end extern "C"
#endif

```

