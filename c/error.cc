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

///
/// \file
/// \brief Frontend for error, implementation
///
/// \author thb-sb

#include "c/sandwich.h"
#include "cc/error.h"

#ifdef __cplusplus
extern "C" {
#endif

SANDWICH_API void sandwich_error_free(struct ::SandwichError* chain) {
  saq::sandwich::error::FreeChain(reinterpret_cast<saq::sandwich::error::ErrorCode*>(chain));
}

#ifdef __cplusplus
} // end extern "C"
#endif
