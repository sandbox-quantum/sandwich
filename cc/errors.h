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
/// \brief Sandwich errors specification

#pragma once

namespace saq::sandwich {


/// \brief Enum Error.
enum class Error : int { 
  kOk = 0,
  kInvalidArgument = 1,
  kMemory = 2,
  kIo = 3,
  kUnknown = 4,
  kInvalidConfiguration = 5,
  kUnsupportedImplementation = 6,
  kUnsupportedProtocol = 7,
  kImplementationProtocolMismatch = 8,
  kProtobuf = 9,
  kNetworkInvalidAddress = 10,
  kNetworkInvalidPort = 11,
  kInvalidContext = 12,
  kBadFd = 13,
  kUnsupportedTunnelMethod = 14,
  kIntegerOverflow = 15,
  kMemoryOverflow = 16,
  kImplementation = 17,
  kInvalidTunnel = 18,
  kInvalidKem = 19,
  kTimeout = 20,
  kNetworkAddressResolve = 21,
  kNetworkConnect = 22,
  kSocketFailed = 23,
  kSocketOptFailed = 24,
  kSocketInvalidAiFamily = 25,
  kConnectionRefused = 26,
  kNetworkUnreachable = 27,
  kSocketPollFailed = 28,
  kInvalidCertificate = 29,
  kUnsupportedCertificate = 30,
  kInvalidPrivateKey = 31,
  kUnsupportedPrivateKey = 32,
  kUnsupportedProtocolVersion = 33,
};


} // end namespace saq::sandwich
