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

#include "cc/context.h"
#include "cc/io/io.h"
#include "cc/io/socket.h"
#include "cc/tests_utils.h"
#include "cc/tunnel.h"

extern "C" {

#include <sys/socket.h>
#include <sys/types.h>

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
void ClientInitiateHandshake(sandwich::Tunnel *client) {
  auto state{client->Handshake()};
  sandwich_assert(state == sandwich::Tunnel::HandshakeState::kWantRead);

  sandwich_assert(client->GetState() ==
                  sandwich::Tunnel::State::kHandshakeInProgress);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 2. The server reads the beginning of the handshake, and answers to
///        the client, by sending the second part of the handshake. At this
///        pointer, the tunnel' state MUST be `kHandshakeInProgress`. The
///        returned value from `Tunnel::Handshake` MUST be `kWantRead`, the
///        client may have to notify the server about an change or an alert.
///
/// \param server Server's tunnel.
void ServerAnswerHandshake(sandwich::Tunnel *server) {
  sandwich_assert(server->GetState() == sandwich::Tunnel::State::kNotConnected);
  auto state{server->Handshake()};
  sandwich_assert(state == sandwich::Tunnel::HandshakeState::kWantRead);

  sandwich_assert(server->GetState() ==
                  sandwich::Tunnel::State::kHandshakeInProgress);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 3. The client acknowledges the handshake by verifying the transcript'
///        signature. Now, the tunnel' state MUST be `kDone`: the record layer
///        is now available to the client. The returned value from
///        `Tunnel::Handshake` therefore MUST be `kHandshakeDone`.
///
/// \param client Client's tunnel.
void ClientCompleteHandshake(sandwich::Tunnel *client) {
  auto state{client->Handshake()};
  sandwich_assert(state == sandwich::Tunnel::HandshakeState::kDone);

  sandwich_assert(client->GetState() ==
                  sandwich::Tunnel::State::kHandshakeDone);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 4. The server acknowledges the handshake too. Now, the tunnel' state
///        MUST be `kDone`: the record layer is now also available to the
///        server. The returned value from `Tunnel::Handshake` MUST be
///        `kHandshakeDone`.
///
/// \param server Server's tunnel.
void ServerCompleteHandshake(sandwich::Tunnel *server) {
  auto state{server->Handshake()};
  sandwich_assert(state == sandwich::Tunnel::HandshakeState::kDone);

  sandwich_assert(server->GetState() ==
                  sandwich::Tunnel::State::kHandshakeDone);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

auto main() -> int {
  auto client = CreateTLSClientContext(
      CertificatePath, sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
      SupportedKEM);
  auto server = CreateTLSServerContext(
      CertificatePath, sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
      PrivateKeyPath, sandwich_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
      SupportedKEM);

  // Create two connected sockets, to use with sandwich::io::Socket.
  std::array<int, 2> fds{0};
  auto err{::socketpair(PF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK, 0, fds.data())};
  sandwich_assert(err == 0);

  // Create I/O interfaces for client and server.
  auto ios{CreateSocketIOPair(fds)};

  // Create tunnels.
  auto client_tunnel = CreateTunnel(&client, std::move(ios.client));
  auto server_tunnel = CreateTunnel(&server, std::move(ios.server));

  // Client initiates the handshake.
  ClientInitiateHandshake(&*client_tunnel);

  // Server answers.
  ServerAnswerHandshake(&*server_tunnel);

  // Client is okay with the signature, the handshake is done.
  ClientCompleteHandshake(&*client_tunnel);

  // The server accesses to the record layer.
  ServerCompleteHandshake(&*server_tunnel);

  // Close the server.
  server_tunnel->Close();
  server_tunnel->GetIO().Close();
  sandwich_assert(server_tunnel->GetState() ==
                  sandwich::tunnel::State::kBeingShutdown);

  auto ioop{client_tunnel->Write(kPingMsg)};
  sandwich_assert(!ioop);
  sandwich_assert(ioop.GetError() == sandwich::tunnel::RecordError::kClosed);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return 0;
}
