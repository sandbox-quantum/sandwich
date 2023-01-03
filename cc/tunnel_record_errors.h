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
/// \brief Enum RecordError in namespace saq::sandwich::tunnel.

#pragma once

namespace saq::sandwich::tunnel {

/// \brief Enum RecordError.
enum class RecordError : int { 
  kOk = 0,
  kWantRead = 1,
  kWantWrite = 2,
  kBeingShutdown = 3,
  kClosed = 4,
  kUnknown = 5,
};

} // end namespace saq::sandwich::tunnel
