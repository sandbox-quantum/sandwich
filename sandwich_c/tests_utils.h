// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * \file
 * \brief Utilities for test.
 *
 * \author sb */

#pragma once

#include <stdio.h>
#include <stdlib.h>

#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif

/** \brief Prints sandwich error and abort on condition.
 *
 * \param e The condition. */
#define sandwich_assert(e)                                                     \
  ((void)((e) ? ((void)0)                                                      \
              : ((void)fprintf(stderr, "%s:%d: failed assertion '%s'\n",       \
                               __FILE_NAME__, __LINE__, #e),                   \
                 abort())))
