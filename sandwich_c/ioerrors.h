// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * \file
 * \brief Sandwich I/O errors specification
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


/** \brief Enum IOError. */
enum SandwichIOError { 
  SANDWICH_IOERROR_OK = 0,
  SANDWICH_IOERROR_IN_PROGRESS = 1,
  SANDWICH_IOERROR_WOULD_BLOCK = 2,
  SANDWICH_IOERROR_REFUSED = 3,
  SANDWICH_IOERROR_CLOSED = 4,
  SANDWICH_IOERROR_INVALID = 5,
  SANDWICH_IOERROR_UNKNOWN = 6,
};
typedef enum SandwichIOError SandwichIOError;


#ifdef __cplusplus
} // end extern "C"
#endif
