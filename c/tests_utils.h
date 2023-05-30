/*
 * Copyright 2023 SandboxAQ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
