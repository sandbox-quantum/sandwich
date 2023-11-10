// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Error handling for the Sandwich library.

#pragma once

#include "sandwich_c/error_codes.h"
#include "sandwich_c/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief An error code.
struct SandwichError {
  /// \brief The encapsulated error.
  struct SandwichError *details;

  /// \brief An optional error string
  const char *msg;

  /// \brief The error kind. See error::ErrorKind enum.
  SandwichErrorKind kind;

  /// \brief The error code.
  int code;
};

/// \brief Free an error chain.
///
/// \param chain Error chain.
SANDWICH_API void sandwich_error_free(struct SandwichError *chain);

/// \brief Create an error stack string from a SandwichError chain.
///
/// \param chain Error chain.
///
/// \return A NUL terminated string describing the SandwichError chain
SANDWICH_API char *
sandwich_error_stack_str_new(const struct SandwichError *chain);

/// \brief Free a an error string (generated from sandwich_error_stack_str_new)
///
/// \param err_str Pointer to error string to free.
///
/// NULL for err_str is allowed.
SANDWICH_API void sandwich_error_stack_str_free(const char *err_str);

#ifdef __cplusplus
} // end extern "C"
#endif
