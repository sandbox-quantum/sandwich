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
/// \brief Sandwich context implementation.
///
/// \author thb-sb

#include "cc/context.h"

namespace saq::sandwich {

Context::Context(const ProtoConfiguration &config)
    : implementation_{config.impl()} {}

Context::~Context() = default;

} // end namespace saq::sandwich