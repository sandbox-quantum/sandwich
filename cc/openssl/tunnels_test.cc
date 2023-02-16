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
/// \brief Unit tests for OpenSSL tunnels.
///
/// \author thb-sb

#include <cerrno>
#include <cstring>
#include <thread>

#include "gtest/gtest.h"

#include "cc/context.h"
#include "cc/error_strings.h"
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

namespace {

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

/// \brief 5. The client sends a "Ping" message to the server.
///
/// \param client Client's tunnel.
[[nodiscard]] auto ClientSendPing(sandwich::Tunnel *client)
    -> testing::AssertionResult {
  auto ioop{client->Write(kPingMsg)};
  if (!ioop) {
    return testing::AssertionFailure()
           << "Expected a successful client I/O op, got an error: "
           << error::GetStringError(ioop.GetError());
  }
  if (ioop.Get() != kPingMsg.size()) {
    return testing::AssertionFailure() << "Expected " << kPingMsg.size()
                                       << " byte(s) sent by the client, got "
                                       << ioop.Get() << " byte(s) sent";
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 6. The server reads the "Ping" message, and sends back a
///           "Pong" message.
///
/// \param server Server's tunnel.
[[nodiscard]] auto ServerReadPingSendPong(sandwich::Tunnel *server)
    -> testing::AssertionResult {
  MsgBuffer buffer{};

  auto ioop{server->Read(buffer)};
  if (!ioop) {
    return testing::AssertionFailure()
           << "Expected a successful server I/O op, got an error: "
           << error::GetStringError(ioop.GetError());
  }
  if (ioop.Get() != kPingMsg.size()) {
    return testing::AssertionFailure() << "Expected " << kPingMsg.size()
                                       << " byte(s) read by the server, got "
                                       << ioop.Get() << " byte(s) read";
  }
  if (buffer != kPingMsg) {
    return testing::AssertionFailure() << "Ping messages mismatch";
  }

  ioop = server->Write(kPongMsg);
  if (!ioop) {
    return testing::AssertionFailure()
           << "Expected a successful server I/O op, got an error: "
           << error::GetStringError(ioop.GetError());
  }
  if (ioop.Get() != kPongMsg.size()) {
    return testing::AssertionFailure() << "Expected " << kPongMsg.size()
                                       << " byte(s) sent by the server, got "
                                       << ioop.Get() << " byte(s) sent";
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 7. Client reads "Pong" message.
///
/// \param client Client's tunnel.
[[nodiscard]] auto ClientReadPong(sandwich::Tunnel *client)
    -> testing::AssertionResult {
  MsgBuffer buffer{};

  auto ioop{client->Read(buffer)};
  if (!ioop) {
    return testing::AssertionFailure()
           << "Expected a successful client I/O op, got an error: "
           << error::GetStringError(ioop.GetError());
  }
  if (ioop.Get() != kPongMsg.size()) {
    return testing::AssertionFailure() << "Expected " << kPongMsg.size()
                                       << " byte(s) read by the client, got "
                                       << ioop.Get() << " byte(s) read";
  }
  if (buffer != kPongMsg) {
    return testing::AssertionFailure() << "Pong messages mismatch";
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 8. Server tries to read something.
///
/// At this stage, the client hasn't written anything. The socket is
/// non-blocking, so the server MUST receive a `kWantRead`, and
/// `RecordResult::WouldBlock` MUST return true.
[[nodiscard]] auto ServerTriesRead(sandwich::Tunnel *server)
    -> testing::AssertionResult {
  MsgBuffer buffer{};

  auto ioop{server->Read(buffer)};
  if (ioop) {
    return testing::AssertionFailure()
           << "Expected a failed server I/O op, got an success: " << ioop.Get();
  }
  if (ioop.GetError() != sandwich::Tunnel::RecordError::kWantRead) {
    return testing::AssertionFailure()
           << "Expected the error code "
           << static_cast<int>(sandwich::Tunnel::RecordError::kWantRead)
           << " for the server, got " << static_cast<int>(ioop.GetError());
  }
  if (!ioop.WouldBlock()) {
    return testing::AssertionFailure()
           << "`IOOpResult::WouldBlock` returns false, but must return true";
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 9. Server closes the tunnel.
///
/// At this stage, the server sent a TLS alert `SHUTDOWN`. The tunnel is now
/// closed to the server side.
[[nodiscard]] auto ServerClosesTunnel(sandwich::Tunnel *server)
    -> testing::AssertionResult {
  const auto state = server->Close();
  if (state != sandwich::Tunnel::State::kBeingShutdown) {
    return testing::AssertionFailure()
           << "Expected kBeingShutdown for the server, got "
           << static_cast<int>(state);
  }

  auto ioop{server->Write(kPingMsg)};
  if (ioop) {
    return testing::AssertionFailure()
           << "Expected a failed server I/O op, got an success: " << ioop.Get();
  }
  if (ioop.GetError() != sandwich::Tunnel::RecordError::kClosed) {
    return testing::AssertionFailure()
           << "Expected the error code "
           << static_cast<int>(sandwich::Tunnel::RecordError::kClosed)
           << " for the server, got " << static_cast<int>(ioop.GetError());
  }

  server->Close();

  const auto tunstate{server->GetState()};
  if (tunstate != sandwich::Tunnel::State::kDisconnected) {
    return testing::AssertionFailure()
           << "Expected kDisconnected for the server, got "
           << static_cast<int>(tunstate);
  }
  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 10. The client tries to write something, but the server asked for
/// closing the tunnel. Therefore, the error `RecordError::kBeingShutdown` is
/// returned.
[[nodiscard]] auto ClientTriesWriteAfterClose(sandwich::Tunnel *client)
    -> testing::AssertionResult {
  auto ioop{client->Write(kPingMsg)};
  if (!ioop) {
    return testing::AssertionFailure()
           << "Expected a successful client I/O op, got an error: "
           << error::GetStringError(ioop.GetError());
  }

  MsgBuffer buffer{};
  ioop = client->Read(buffer);
  if (ioop) {
    return testing::AssertionFailure()
           << "Expected a failed client I/O op, got " << ioop.Get();
  }

  if (ioop.GetError() != sandwich::Tunnel::RecordError::kBeingShutdown) {
    return testing::AssertionFailure()
           << "Expected the error code "
           << static_cast<int>(sandwich::Tunnel::RecordError::kBeingShutdown)
           << " for the client, got " << static_cast<int>(ioop.GetError());
  }
  const auto tunstate{client->Close()};
  if (tunstate != sandwich::Tunnel::State::kDisconnected) {
    return testing::AssertionFailure()
           << "Expected kDisconnected for the client, got "
           << static_cast<int>(tunstate);
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

/// \brief 11. Create a new tunnel using the existing I/O interface from an
/// old tunnel.
auto RecycleIOToNewTunnel(std::unique_ptr<sandwich::Context> *ctx,
                          std::unique_ptr<sandwich::Tunnel> *old_tun)
    -> testing::AssertionResult {
  auto io = (*old_tun)->ReleaseIO();
  if (!io) {
    return testing::AssertionFailure()
           << "Expected a non-null I/O interface from `ReleaseIO`, got null";
  }
  if (auto ares = CreateTunnel(ctx, std::move(io), old_tun); !ares) {
    return ares << "Failed to create a new tunnel from an old I/O interface";
  }

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return testing::AssertionSuccess();
}

} // end anonymous namespace

TEST(OpenSSLTunnels, OpenSSLTunnels) {
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

  // Client sends "Ping".
  ASSERT_TRUE(ClientSendPing(&*client_tunnel)) << "`ClientSendPing` failed";

  // Server receives "Ping" and sends "Pong".
  ASSERT_TRUE(ServerReadPingSendPong(&*server_tunnel))
      << "`ServerReadPingSendPong` failed";

  // Client receives "Pong".
  ASSERT_TRUE(ClientReadPong(&*client_tunnel)) << "`ClientReadPong` failed";

  // Server tries to read, it triggers a `WANT_READ`, and WouldBlock returns
  // true.
  ASSERT_TRUE(ServerTriesRead(&*server_tunnel)) << "`ServerTriesRead` failed";

  // Server closes the tunnel  by calling `Close`. It triggers a `SHUTDOWN`
  // TLS alert.
  ASSERT_TRUE(ServerClosesTunnel(&*server_tunnel))
      << "`ServerClosesTunnel` failed";

  // Client tries to write to the tunnel.
  // Because the server sent a `SHUTDOWN` TLS alert, the read after
  // the write fails and return `RecordState::kBeingShutdown`.
  ASSERT_TRUE(ClientTriesWriteAfterClose(&*client_tunnel))
      << "`ClientTriesWriteAfterClose` failed";

  {
    // Flushing client and server sockets
    sandwich::io::IO::OpResult ioop{};
    do {
      MsgBuffer buf{};
      ioop = client_tunnel->GetIO().Read(
          buf, sandwich::tunnel::State::kDisconnected);
    } while (ioop.count > 0);
    do {
      MsgBuffer buf{};
      ioop = server_tunnel->GetIO().Read(
          buf, sandwich::tunnel::State::kDisconnected);
    } while (ioop.count > 0);
  }

  // Create a new server tunnel using the existing I/O interface from the
  // old client tunnel.
  ASSERT_TRUE(RecycleIOToNewTunnel(&server, &server_tunnel))
      << "`RecycleIOToNewTunnel` with server tunnel failed";

  // Create a new client tunnel using the existing I/O interface from the
  // old client tunnel.
  ASSERT_TRUE(RecycleIOToNewTunnel(&client, &client_tunnel))
      << "`RecycleIOToNewTunnel` with client tunnel failed";

  // Redo: client initiates the handshake.
  ASSERT_TRUE(ClientInitiateHandshake(&*client_tunnel))
      << "`ClientInitiateHandshake` failed";

  // Redo: server answers.
  ASSERT_TRUE(ServerAnswerHandshake(&*server_tunnel))
      << "`ServerAnswerHandshake` failed";

  // Redo: client is okay with the signature, the handshake is done.
  ASSERT_TRUE(ClientCompleteHandshake(&*client_tunnel))
      << "`ClientCompleteHandshake` failed";

  // Redo: the server accesses to the record layer.
  ASSERT_TRUE(ServerCompleteHandshake(&*server_tunnel))
      << "`ServerCompleteHandshake` failed";

  client_tunnel->Close();
  server_tunnel->Close();
}
