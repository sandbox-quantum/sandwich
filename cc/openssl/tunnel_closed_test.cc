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
/// \brief Test the case when the underlying I/O gets closed.
///
/// \author thb-sb

#include "gtest/gtest.h"

#include "cc/context.h"
#include "cc/io/io.h"
#include "cc/io/socket.h"
#include "cc/tests_utils.h"
#include "cc/tunnel.h"

extern "C" {

#include <sys/socket.h>
#include <sys/types.h>

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#endif

} // end extern "C"

/// \brief Path to the certificate.
constexpr std::string_view CertificatePath{
    "testdata/cert.pem"};

/// \brief Path to the private key.
constexpr std::string_view PrivateKeyPath{"testdata/key.pem"};

/// \brief Supported KEM.
constexpr std::string_view SupportedKEM{"kyber1024"};

/// \brief 1. Start the handshake from the client.
///
/// This function checks the following assertion:
///   * Asynchronous tunnels: the client starts the handshake. At this point,
///     the tunnel' state MUST be `kHandshakeInProgress`. The returned value
///     from `Tunnel::Handshake` MUST be `kWantRead`, because the client
///     sent the Hello,Key,Share part of the TLS1.3 handshake, and it waits
///     for the server's response ("wants to read from the socket").
///
/// \param client Client's tunnel.
[[nodiscard]] auto ClientInitiateHandshake(sandwich::Tunnel *client)
    -> testing::AssertionResult {
  auto state{client->Handshake()};
  if (state != sandwich::Tunnel::HandshakeState::kWantRead) {
    return testing::AssertionFailure()
           << "Expected `kWantRead` for the client, got "
           << static_cast<int>(state);
  }

  auto tunstate{client->GetState()};
  if (tunstate != sandwich::Tunnel::State::kHandshakeInProgress) {
    return testing::AssertionFailure()
           << "Expected `kHandshakeInProgress` for the client, got "
           << static_cast<int>(tunstate);
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 2. The server reads the beginning of the handshake, and answers to
///        the client, by sending the second part of the handshake. At this
///        pointer, the tunnel' state MUST be `kHandshakeInProgress`. The
///        returned value from `Tunnel::Handshake` MUST be `kWantRead`, the
///        client may have to notify the server about an change or an alert.
///
/// \param server Server's tunnel.
[[nodiscard]] auto ServerAnswerHandshake(sandwich::Tunnel *server)
    -> testing::AssertionResult {
  auto tunstate{server->GetState()};
  if (tunstate != sandwich::Tunnel::State::kNotConnected) {
    return testing::AssertionFailure()
           << "Expected `kNotConnected` for the server, got "
           << static_cast<int>(tunstate);
  }

  auto state{server->Handshake()};
  if (state != sandwich::Tunnel::HandshakeState::kWantRead) {
    return testing::AssertionFailure()
           << "Expected `kWantRead` for the server, got "
           << static_cast<int>(state);
  }

  tunstate = server->GetState();
  if (tunstate != sandwich::Tunnel::State::kHandshakeInProgress) {
    return testing::AssertionFailure()
           << "Expected `kHandshakeInProgress` for the server, got "
           << static_cast<int>(tunstate);
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 3. The client acknowledges the handshake by verifying the transcript'
///        signature. Now, the tunnel' state MUST be `kDone`: the record layer
///        is now available to the client. The returned value from
///        `Tunnel::Handshake` therefore MUST be `kHandshakeDone`.
///
/// \param client Client's tunnel.
[[nodiscard]] auto ClientCompleteHandshake(sandwich::Tunnel *client)
    -> testing::AssertionResult {
  auto state{client->Handshake()};
  if (state != sandwich::Tunnel::HandshakeState::kDone) {
    return testing::AssertionFailure()
           << "Expected `kDone` for the client, got "
           << static_cast<int>(state);
  }

  auto tunstate{client->GetState()};
  if (tunstate != sandwich::Tunnel::State::kHandshakeDone) {
    return testing::AssertionFailure()
           << "Expected `kHandshakeDone` for the client, got "
           << static_cast<int>(tunstate);
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 4. The server acknowledges the handshake too. Now, the tunnel' state
///        MUST be `kDone`: the record layer is now also available to the
///        server. The returned value from `Tunnel::Handshake` MUST be
///        `kHandshakeDone`.
///
/// \param server Server's tunnel.
[[nodiscard]] auto ServerCompleteHandshake(sandwich::Tunnel *server)
    -> testing::AssertionResult {
  auto state{server->Handshake()};
  if (state != sandwich::Tunnel::HandshakeState::kDone) {
    return testing::AssertionFailure()
           << "Expected `kDone` for the server, got "
           << static_cast<int>(state);
  }

  auto tunstate{server->GetState()};
  if (tunstate != sandwich::Tunnel::State::kHandshakeDone) {
    return testing::AssertionFailure()
           << "Expected `kHandshakeDone` for the server, got "
           << static_cast<int>(tunstate);
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

TEST(OpenSSLClosedTunnels, OpenSSLClosedTunnels) {
  std::unique_ptr<sandwich::Context> client;
  ASSERT_TRUE(CreateTLSClientContext(
      CertificatePath, sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
      SupportedKEM, &client))
      << "Failed to create the TLS client context";

  std::unique_ptr<sandwich::Context> server;
  ASSERT_TRUE(CreateTLSServerContext(
      CertificatePath, sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
      PrivateKeyPath, sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
      SupportedKEM, &server))
      << "Failed to create the TLS server context";

  // Create two connected sockets, to use with sandwich::io::Socket.
  std::array<int, 2> fds{0};
#ifdef SOCK_NONBLOCK
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  auto err{::socketpair(PF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK, 0, fds.data())};
  ASSERT_EQ(err, 0) << "`socketpair` returned an error: " << err << '('
                    << ::strerror(errno) << ')';
#else
  auto err{::socketpair(PF_LOCAL, SOCK_STREAM, 0, fds.data())};
  ASSERT_EQ(err, 0) << "`socketpair` returned an error: " << err << '('
                    << ::strerror(errno) << ')';
  for (auto fd : fds) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    ASSERT_NE(flags, -1) << "`fcntl` returned an error: " << flags << '('
                         << ::strerror(errno) << ')';
    flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    ASSERT_NE(flags, -1) << "`fcntl` returned an error: " << flags << '('
                         << ::strerror(errno) << ')';
  }
#endif

  // Create I/O interfaces for client and server.
  IOPair ios;
  ASSERT_TRUE(CreateSocketIOPair(fds, &ios)) << "Failed to create the IOPair";

  // Create tunnels.
  std::unique_ptr<sandwich::Tunnel> client_tunnel;
  ASSERT_TRUE(CreateTunnel(&client, std::move(ios.client), &client_tunnel))
      << "Failed to create the client tunnel";
  std::unique_ptr<sandwich::Tunnel> server_tunnel;
  ASSERT_TRUE(CreateTunnel(&server, std::move(ios.server), &server_tunnel))
      << "Failed to create the server tunnel";

  // Client initiates the handshake.
  ASSERT_TRUE(ClientInitiateHandshake(&*client_tunnel))
      << "`ClientInitiateHandshake` failed";

  // Server answers.
  ASSERT_TRUE(ServerAnswerHandshake(&*server_tunnel))
      << "`ServerAnswerHandshake` failed";

  // Client is okay with the signature, the handshake is done.
  ASSERT_TRUE(ClientCompleteHandshake(&*client_tunnel))
      << "`ClientCompleteHandshake` failed";

  // The server accesses to the record layer.
  ASSERT_TRUE(ServerCompleteHandshake(&*server_tunnel))
      << "`ServerCompleteHandshake` failed";

  // Close the server.
  server_tunnel->Close();
  server_tunnel->GetIO().Close();
  ASSERT_EQ(server_tunnel->GetState(), sandwich::tunnel::State::kBeingShutdown)
      << "Invalid server tunnel state";

  auto ioop{client_tunnel->Write(kPingMsg)};
  ASSERT_FALSE(ioop) << "Expected failed client I/O op, got " << ioop.Get();
  ASSERT_EQ(ioop.GetError(), sandwich::tunnel::RecordError::kClosed)
      << "Invalid error code for the I/O op";

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}
