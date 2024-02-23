// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "sandwich_c/export.h"

#ifdef __cplusplus
extern "C" {
#endif

///
/// \file
/// \brief Top-level context for the Sandwich library.

/// \brief Top-level Sandwich context.
struct SandwichContext;

/// \brief Create a top-level Sandwich context.
///
/// \return A new top-level Sandwich context.
SANDWICH_API struct SandwichContext *sandwich_lib_context_new(void);

/// \brief Free a top-level Sandwich context.
///
/// \param[in] sw Top-level Sandwich context to free.
///
/// NULL for `sw` is allowed.
SANDWICH_API void sandwich_lib_context_free(struct SandwichContext *sw);

#ifdef __cplusplus
} // end extern "C"
#endif
