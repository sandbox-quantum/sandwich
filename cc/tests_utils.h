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
/// \brief Functions for unit tests.
///
/// \author thb-sb

#pragma once

#include <array>
#include <span>
#include <string_view>

#include "gtest/gtest.h"

#include "cc/context.h"
#include "cc/tunnel.h"
#include "proto/api/v1/configuration.pb.h"

extern "C" {

#include <stdio.h>
#include <stdlib.h>

} // end extern "C"

#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif

#ifndef SANDWICH_ASSERT
/// \brief Prints sandwich error and abort on condition.
///
/// \param e The condition.
#define sandwich_assert(e)                                               \
  ((void)((e) ? ((void)0)                                                \
              : ((void)fprintf(stderr, "%s:%d: failed assertion '%s'\n", \
                               __FILE_NAME__, __LINE__, #e),             \
                 abort())))
#define SANDWICH_ASSERT
#endif

/// \brief Alias to saq::sandwich.
namespace sandwich = saq::sandwich;

/// \brief Alias to sandwich proto.
namespace sandwich_proto = sandwich::proto;

/// \brief Alias to sandwich proto API.
namespace sandwich_api = sandwich_proto::api::v1;

/// \brief Simple message buffer.
using MsgBuffer = std::array<std::byte, 4>;

/// \brief « Ping » message.
constexpr MsgBuffer kPingMsg{std::byte{'P'}, std::byte{'i'}, std::byte{'n'},
                             std::byte{'g'}};

/// \brief « Pong » message.
constexpr MsgBuffer kPongMsg{std::byte{'P'}, std::byte{'o'}, std::byte{'n'},
                             std::byte{'g'}};

/// \brief Pair of I/O interfaces, one for the client, one for the server.
struct IOPair {
  /// \brief Client I/O interface.
  std::unique_ptr<sandwich::io::IO> client;

  /// \brief Server I/O interface.
  std::unique_ptr<sandwich::io::IO> server;
};

/// \brief Create a new configuration from a mode, an impl and a protocol.
///
/// \param mode Mode.
/// \param impl Implementation.
/// \param proto Protocol.
/// \param[out] config Configuration to write.
///
/// \return A new configuration.
[[nodiscard]] auto NewConfiguration(sandwich_proto::Mode mode,
                                    sandwich_api::Implementation impl,
                                    sandwich_api::Protocol proto,
                                    sandwich_api::Configuration *config)
    -> testing::AssertionResult;

/// \brief Add a certificate to the list of trusted certificate for clients,
/// or set the certificate for server.
///
/// \param config TLS configuration.
/// \param certpath Path to the certificate.
/// \param certfmt Certificate format.
[[nodiscard]] auto TLSConfigurationSetCertificate(
    sandwich_api::Configuration *config, const std::string_view &certpath,
    sandwich_api::ASN1EncodingFormat certfmt) -> testing::AssertionResult;

/// \brief Set the private key to a TLS configuration.
///
/// \param config TLS configuration.
/// \param keypath Path to the private key.
/// \param keyfmt Private key format.
[[nodiscard]] auto TLSConfigurationSetPrivateKey(
    sandwich_api::Configuration *config, const std::string_view &keypath,
    sandwich_api::ASN1EncodingFormat keyfmt) -> testing::AssertionResult;

/// \brief Append a KEM to a TLS configuration.
///
/// \param config TLS configuration.
/// \param kem KEM to append to config.
[[nodiscard]] auto TLSConfigurationAddKEM(sandwich_api::Configuration *config,
                                          const std::string_view &kem)
    -> testing::AssertionResult;

/// \brief Append KEMs to a TLS configuration.
///
/// \param config TLS configuration.
/// \param kems KEM to append to config.
[[nodiscard]] auto TLSConfigurationAddKEMs(
    sandwich_api::Configuration *config,
    const std::span<const std::string_view> &kems) -> testing::AssertionResult;

/// \brief Create a Sandwich context from a configuration.
///
/// \param config Configuration.
/// \param[out] context Context unique pointer to fill.
[[nodiscard]] auto CreateContext(const sandwich_api::Configuration &config,
                                 std::unique_ptr<sandwich::Context> *context)
    -> testing::AssertionResult;

/// \brief Create a Sandwich tunnel from a context and an I/O interface.
///
/// \param context Configuration.
/// \param ioint I/O interface.
/// \param[out] tun Tunnel unique pointer to fill.
///
/// \return The tunnel.
[[nodiscard]] auto CreateTunnel(std::unique_ptr<sandwich::Context> *context,
                                std::unique_ptr<sandwich::io::IO> ioint,
                                std::unique_ptr<sandwich::Tunnel> *tun)
    -> testing::AssertionResult;

/// \brief Create a TLS client context from a trusted certificate and a KEM.
///
/// \param certpath Path to the certificate.
/// \param certfmt Certificate format.
/// \param kem KEM to use.
/// \param[out] context Context unique pointer to fill.
[[nodiscard]] auto CreateTLSClientContext(
    const std::string_view &certpath, sandwich_api::ASN1EncodingFormat certfmt,
    const std::string_view &kem, std::unique_ptr<sandwich::Context> *context)
    -> testing::AssertionResult;

/// \brief Create a TLS server context from a certificate,a key and a KEM.
///
/// \param certpath Path to the certificate.
/// \param certfmt Certificate format.
/// \param keypath Path to the private key.
/// \param keyfmt Private key format.
/// \param kem KEM to use.
/// \param[out] context Context unique pointer to fill.
[[nodiscard]] auto CreateTLSServerContext(
    const std::string_view &certpath, sandwich_api::ASN1EncodingFormat certfmt,
    const std::string_view &keypath, sandwich_api::ASN1EncodingFormat keyfmt,
    const std::string_view &kem, std::unique_ptr<sandwich::Context> *context)
    -> testing::AssertionResult;

/// \brief Create two connected I/O interfaces using
/// saq::sandwich::io::Socket.
///
/// \param fds File descriptors.
/// \param[out] pair The IOPair to fill.
///
/// The first file descriptor in `fds` is the client's.
/// and last file descriptor in `fds` is the server's
[[nodiscard]] auto CreateSocketIOPair(const std::array<int, 2> &fds,
                                      IOPair *pair) -> testing::AssertionResult;
