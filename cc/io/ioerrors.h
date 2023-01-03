// Copyright 2022 SandboxAQ
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
/// \brief Enum IOError in namespace saq::sandwich::io.

#pragma once

namespace saq::sandwich::io {

/// \brief Enum IOError.
enum class IOError : int { 
  kOk = 0,
  kInProgress = 1,
  kWouldBlock = 2,
  kRefused = 3,
  kClosed = 4,
  kInvalid = 5,
  kUnknown = 6,
};

} // end namespace saq::sandwich::io
