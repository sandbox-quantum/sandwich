// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Unit tests for OpenSSL tunnels using the C frontend.
///
/// \author thb-sb and jgoertzen-sb

#include <array>
#include <random>
#include <thread>

#include "proto/api/v1/configuration.pb.h"
#include "proto/api/v1/listener_configuration.pb.h"
#include "proto/sandwich.pb.h"

#include "tools/cpp/runfiles/runfiles.h"

extern "C" {

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sandwich_c/listener.h"
#include "sandwich_c/sandwich.h"
#include "sandwich_c/tunnel.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif

/** \brief Prints sandwich error and abort on condition.
 *
 * \param e The condition. */
#define sandwich_assert(e)                                                     \
  ((void)((e) ? ((void)0)                                                      \
              : ((void)fprintf(stderr, "%s:%d: failed assertion '%s'\n",       \
                               __FILE_NAME__, __LINE__, #e),                   \
                 abort())))

} // end extern "C"

using bazel::tools::cpp::runfiles::Runfiles;

namespace {

/// \brief Simple message buffer.
using MsgBuffer = std::array<std::byte, 4>;
/// \brief « Ping » message.
constexpr MsgBuffer kPingMsg{std::byte{'P'}, std::byte{'i'}, std::byte{'n'},
                             std::byte{'g'}};

/// \brief « Pong » message.
constexpr MsgBuffer kPongMsg{std::byte{'P'}, std::byte{'o'}, std::byte{'n'},
                             std::byte{'g'}};

/// \brief Create a configuration.
///
/// \param mode Mode.
/// \param impl Implementation.
///
/// \return The configuration.
auto NewTLSConfiguration(
    const saq::sandwich::proto::Mode mode,
    const saq::sandwich::proto::api::v1::Implementation impl)
    -> saq::sandwich::proto::api::v1::Configuration {
  saq::sandwich::proto::api::v1::Configuration config{};

  config.set_impl(impl);

  if (mode == saq::sandwich::proto::Mode::MODE_CLIENT) {
    config.mutable_client()->mutable_tls()->mutable_common_options();
  } else if (mode == saq::sandwich::proto::Mode::MODE_SERVER) {
    config.mutable_server()->mutable_tls()->mutable_common_options();
  }

  return config;
}

/// \brief Deleter for SandwichContext.
using SandwichContextDeleter = std::function<void(struct ::SandwichContext *)>;

/// \brief Deleter for SandwichTunnelContext
using SandwichTunnelContextDeleter =
    std::function<void(struct ::SandwichTunnelContext *)>;

/// \brief Create a Sandwich context for the client.
///
/// \param runfiles Bazel runfiles context.
///
/// \return A Sandwich context for the client.
auto CreateClientContext(std::unique_ptr<Runfiles> &runfiles)
    -> std::unique_ptr<struct ::SandwichTunnelContext,
                       SandwichTunnelContextDeleter> {
  auto config{NewTLSConfiguration(saq::sandwich::proto::Mode::MODE_CLIENT,
                                  saq::sandwich::proto::api::v1::
                                      Implementation::IMPL_OPENSSL1_1_1_OQS)};

  config.mutable_client()
      ->mutable_tls()
      ->mutable_common_options()
      ->mutable_tls13()
      ->add_ke("kyber1024");

  auto *cert = config.mutable_client()
                   ->mutable_tls()
                   ->mutable_common_options()
                   ->mutable_x509_verifier()
                   ->add_trusted_cas()
                   ->mutable_static_();
  cert->mutable_data()->set_filename(runfiles->Rlocation(
      "sandwich/testdata/falcon1024.cert.pem"));
  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_PEM);

  std::string encoded_configuration{};
  sandwich_assert(config.SerializeToString(&encoded_configuration) == true);

  struct ::SandwichTunnelContext *ctx = nullptr;
  std::unique_ptr<struct SandwichContext, SandwichContextDeleter> sw(
      ::sandwich_lib_context_new(),
      [](struct SandwichContext *sw) { ::sandwich_lib_context_free(sw); });
  ::SandwichTunnelContextConfigurationSerialized serialized = {
      .src = encoded_configuration.data(),
      .n = encoded_configuration.size(),
  };

  const auto *err = ::sandwich_tunnel_context_new(&*sw, serialized, &ctx);
  sandwich_assert(err == nullptr);

  return {ctx, [](struct ::SandwichTunnelContext *c) {
            ::sandwich_tunnel_context_free(c);
          }};
}

/// \brief Create a Sandwich context for the server.
///
/// \param runfiles Bazel runfiles context.
///
/// \return A Sandwich context for the server.
auto CreateServerContext(std::unique_ptr<Runfiles> &runfiles)
    -> std::unique_ptr<struct ::SandwichTunnelContext,
                       SandwichTunnelContextDeleter> {
  auto config{NewTLSConfiguration(saq::sandwich::proto::Mode::MODE_SERVER,
                                  saq::sandwich::proto::api::v1::
                                      Implementation::IMPL_OPENSSL1_1_1_OQS)};

  config.mutable_server()
      ->mutable_tls()
      ->mutable_common_options()
      ->mutable_tls13()
      ->add_ke("kyber1024");

  config.mutable_server()
      ->mutable_tls()
      ->mutable_common_options()
      ->mutable_empty_verifier();

  auto *cert = config.mutable_server()
                   ->mutable_tls()
                   ->mutable_common_options()
                   ->mutable_identity()
                   ->mutable_certificate()
                   ->mutable_static_();
  cert->mutable_data()->set_filename(runfiles->Rlocation(
      "sandwich/testdata/falcon1024.cert.pem"));
  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_PEM);

  auto *key = config.mutable_server()
                  ->mutable_tls()
                  ->mutable_common_options()
                  ->mutable_identity()
                  ->mutable_private_key()
                  ->mutable_static_();
  key->mutable_data()->set_filename(runfiles->Rlocation(
      "sandwich/testdata/falcon1024.key.pem"));
  key->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                      ENCODING_FORMAT_PEM);

  std::string encoded_configuration{};
  sandwich_assert(config.SerializeToString(&encoded_configuration) == true);

  std::unique_ptr<struct SandwichContext, SandwichContextDeleter> sw(
      ::sandwich_lib_context_new(),
      [](struct SandwichContext *sw) { ::sandwich_lib_context_free(sw); });

  struct ::SandwichTunnelContext *ctx = nullptr;
  struct ::SandwichTunnelContextConfigurationSerialized serialized {
    .src = encoded_configuration.data(), .n = encoded_configuration.size(),
  };

  const auto *err = ::sandwich_tunnel_context_new(&*sw, serialized, &ctx);
  sandwich_assert(err == nullptr);

  return {ctx, [](struct ::SandwichTunnelContext *c) {
            ::sandwich_tunnel_context_free(c);
          }};
}

/// \brief Deleter for SandwichListener
using SandwichListenerDeleter =
    std::function<void(struct ::SandwichListener *)>;

/// \brief Create a TCP Listener using sandwich API.
///
/// \return A Sandwich TCP Listener for the server.
auto CreateTCPListener(std::string ipaddr, uint16_t port, bool is_blocking)
    -> std::unique_ptr<struct ::SandwichListener, SandwichListenerDeleter> {
  saq::sandwich::proto::api::v1::ListenerConfiguration config{};

  config.mutable_tcp()->mutable_addr()->set_hostname(ipaddr);
  config.mutable_tcp()->mutable_addr()->set_port((uint32_t)port);
  if (is_blocking) {
    config.mutable_tcp()->set_blocking_mode(
        saq::sandwich::proto::api::v1::BlockingMode::
            BLOCKINGMODE_BLOCKING);
  } else {
    config.mutable_tcp()->set_blocking_mode(
        saq::sandwich::proto::api::v1::BlockingMode::
            BLOCKINGMODE_NONBLOCKING);
  }
  std::string encoded_configuration{};
  sandwich_assert(config.SerializeToString(&encoded_configuration) == true);
  struct ::SandwichListener *listener = nullptr;
  const auto err = ::sandwich_listener_new(
      encoded_configuration.data(), encoded_configuration.size(), &listener);
  sandwich_assert(err == nullptr);
  sandwich_assert(listener != nullptr);
  return {listener,
          [](struct ::SandwichListener *l) { ::sandwich_listener_free(l); }};
}

/// \brief Deleter for Sandwich Tunnel.
using SandwichTunnelDeleter = std::function<void(struct ::SandwichTunnel *)>;

/// \brief Create a tunnel from a context and an I/O interface.
///
/// \param ctx Context.
/// \param io IO interface.
/// \param configuration Configuration.
///
/// This function succeed.
///
/// \return The tunnel.
[[nodiscard]] auto CreateTunnel(
    struct ::SandwichTunnelContext *ctx, const struct ::SandwichTunnelIO &io,
    const struct ::SandwichTunnelConfigurationSerialized &configuration)
    -> std::unique_ptr<struct ::SandwichTunnel, SandwichTunnelDeleter> {
  struct ::SandwichTunnel *tun{nullptr};
  const auto *err{::sandwich_tunnel_new(ctx, &io, configuration, &tun)};
  sandwich_assert(err == nullptr);
  sandwich_assert(tun != nullptr);

  return {tun, [](struct ::SandwichTunnel *t) { ::sandwich_tunnel_free(t); }};
}

/// \brief 1. Start the handshake from the client.
///
/// This function checks the following assertion:
///   * Asynchronous tunnels: the client starts the handshake. At this point,
///     the tunnel' state MUST be `kHandshakeInProgress`. The returned value
///     from `Tunnel::Handshake` MUST be `kWantRead`, because the client
///     sent the Hello,Key,Share part of the TLS1.3 handshake, and it waits
///     for the server's response (« wants to read from the socket»).
///
/// \param client Client's tunnel.
void ClientInitiateHandshake(struct ::SandwichTunnel *client) {
  enum ::SandwichTunnelHandshakeState state;
  const auto err{::sandwich_tunnel_handshake(client, &state)};
  if (err != NULL) {
    std::cout << "err: " << err->msg << " state: " << state << std::endl;
    perror("ClientInitiateHandshake");
  }
  sandwich_assert(err == NULL);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 2. The server reads the beginning of the handshake, and answers to
///        the client, by sending the second part of the handshake. At this
///        pointer, the tunnel' state MUST be `kHandshakeInProgress`. The
///        returned value from `Tunnel::Handshake` MUST be `kWantRead`, the
///        client may have to notify the server about an change or an alert.
///
/// \param server Server's tunnel.
void ServerAnswerHandshake(struct ::SandwichTunnel *server) {
  sandwich_assert(::sandwich_tunnel_state(server) ==
                  SANDWICH_TUNNEL_STATE_NOT_CONNECTED);
  enum ::SandwichTunnelHandshakeState state;
  const auto err{::sandwich_tunnel_handshake(server, &state)};
  if (err != NULL) {
    std::cout << "err: " << err->msg << " errno: " << errno
              << " state: " << state << std::endl;
    perror("ServerAnswerHandshake");
  }
  sandwich_assert(err == NULL);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 3. The client acknowledges the handshake by verifying the transcript'
///        signature. Now, the tunnel' state MUST be `kDone`: the record layer
///        is now available to the client. The returned value from
///        `Tunnel::Handshake` therefore MUST be `kHandshakeDone`.
///
/// \param client Client's tunnel.
void ClientCompleteHandshake(struct ::SandwichTunnel *client) {
  enum ::SandwichTunnelHandshakeState state;
  auto err{::sandwich_tunnel_handshake(client, &state)};
  if (err != NULL) {
    std::cout << "err: " << err->msg << " errno: " << errno
              << " state: " << state << std::endl;
    perror("ClientCompleteHandshake");
  }
  sandwich_assert(err == NULL);
  sandwich_assert(state == SANDWICH_TUNNEL_HANDSHAKESTATE_DONE);

  sandwich_assert(sandwich_tunnel_state(client) ==
                  SANDWICH_TUNNEL_STATE_HANDSHAKE_DONE);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 4. The server acknowledges the handshake too. Now, the tunnel' state
///        MUST be `kDone`: the record layer is now also available to the
///        server. The returned value from `Tunnel::Handshake` MUST be
///        `kHandshakeDone`.
///
/// \param server Server's tunnel.
void ServerCompleteHandshake(struct ::SandwichTunnel *server) {
  enum ::SandwichTunnelHandshakeState state;
  auto err{::sandwich_tunnel_handshake(server, &state)};
  if (err != NULL) {
    std::cout << "err: " << err << " " << err->msg << " state: " << state
              << std::endl;
    perror("ServerCompleteHandshake");
  }
  sandwich_assert(err == NULL);

  sandwich_assert(::sandwich_tunnel_state(server) ==
                  SANDWICH_TUNNEL_STATE_HANDSHAKE_DONE);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 5. The client sends a « Ping » message to the server.
///
/// \param client Client's tunnel.
void ClientSendPing(struct ::SandwichTunnel *client) {
  size_t w{0};
  const auto err{
      ::sandwich_tunnel_write(client, kPingMsg.data(), kPingMsg.size(), &w)};
  sandwich_assert(err == SANDWICH_TUNNEL_RECORDERROR_OK);
  sandwich_assert(w == kPingMsg.size());

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 6. The server reads the « Ping » message, and sends back a
///           « Pong » message.
///
/// \param server Server's tunnel.
void ServerReadPingSendPong(struct ::SandwichTunnel *server) {
  MsgBuffer buffer{};
  size_t r{0};

  auto err{::sandwich_tunnel_read(server, buffer.data(), buffer.size(), &r)};
  sandwich_assert(err == SANDWICH_TUNNEL_RECORDERROR_OK);
  sandwich_assert(r == kPingMsg.size());
  sandwich_assert(buffer == kPingMsg);

  r = 0;
  err = ::sandwich_tunnel_write(server, kPongMsg.data(), kPongMsg.size(), &r);
  sandwich_assert(err == SANDWICH_TUNNEL_RECORDERROR_OK);
  sandwich_assert(r == kPongMsg.size());

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 7. Client reads « Pong » message.
///
/// \param client Client's tunnel.
void ClientReadPong(struct ::SandwichTunnel *client) {
  MsgBuffer buffer{};
  size_t r{0};

  auto err{::sandwich_tunnel_read(client, buffer.data(), buffer.size(), &r)};
  sandwich_assert(err == SANDWICH_TUNNEL_RECORDERROR_OK);
  sandwich_assert(r == kPongMsg.size());
  sandwich_assert(buffer == kPongMsg);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 8. Server closes the tunnel.
///
/// At this stage, the server sent a TLS alert `SHUTDOWN`. The tunnel is now
/// closed to the server side.
void ServerClosesTunnel(struct ::SandwichTunnel *server) {
  ::sandwich_tunnel_close(server);

  size_t w{0};
  const auto err{
      ::sandwich_tunnel_write(server, kPingMsg.data(), kPingMsg.size(), &w)};
  sandwich_assert(err == SANDWICH_TUNNEL_RECORDERROR_CLOSED);
  sandwich_assert(::sandwich_tunnel_state(server) ==
                  SANDWICH_TUNNEL_STATE_DISCONNECTED);
  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

} // end anonymous namespace

bool SERVER_READY = false;

void client_thread(std::string server_hostname, uint16_t server_port) {
  while (!SERVER_READY)
    ;
  struct ::SandwichIOOwned *client_io;
  std::string error;
  std::unique_ptr<Runfiles> runfiles(
      Runfiles::CreateForTest(BAZEL_CURRENT_REPOSITORY, &error));
  sandwich_assert(runfiles != nullptr);
  auto client = CreateClientContext(runfiles);
  sandwich_io_client_tcp_new(server_hostname.c_str(), server_port, true,
                             &client_io);

  struct ::SandwichTunnelIO io {
    .base = *client_io->io, .set_state = nullptr,
  };
  // Create tunnels.
  auto client_tunnel =
      CreateTunnel(&*client, io, SandwichTunnelConfigurationVerifierEmpty);

  // Client initiates the handshake.
  ClientInitiateHandshake(&*client_tunnel);

  // Client is okay with the signature, the handshake is done.
  ClientCompleteHandshake(&*client_tunnel);

  // Client sends « Ping ».
  ClientSendPing(&*client_tunnel);

  // Client receives « Pong ».
  ClientReadPong(&*client_tunnel);

  // Do some cleanup
  sandwich_io_owned_free(&*client_io);
}

void server_thread(std::string server_hostname, uint16_t server_port) {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(
      Runfiles::CreateForTest(BAZEL_CURRENT_REPOSITORY, &error));
  sandwich_assert(runfiles != nullptr);
  auto server = CreateServerContext(runfiles);
  auto server_listener =
      CreateTCPListener(server_hostname.c_str(), server_port, true);
  sandwich_assert(sandwich_listener_listen(&*server_listener) ==
                  SANDWICH_IOERROR_OK);

  SERVER_READY = true;
  enum SandwichIOError err;
  struct SandwichIOOwned *listener_io;
  err = sandwich_listener_accept(&*server_listener, &listener_io);
  sandwich_assert(err == SANDWICH_IOERROR_OK);
  struct ::SandwichTunnelIO io {
    .base = *listener_io->io, .set_state = nullptr,
  };
  auto server_tunnel =
      CreateTunnel(&*server, io, SandwichTunnelConfigurationVerifierEmpty);

  // Server answers.
  ServerAnswerHandshake(&*server_tunnel);

  // The server accesses to the record layer.
  ServerCompleteHandshake(&*server_tunnel);

  // Server receives « Ping » and sends « Pong ».
  ServerReadPingSendPong(&*server_tunnel);

  // Server closes the tunnel  by calling `Close`. It triggers a `SHUTDOWN`
  // TLS alert.
  ServerClosesTunnel(&*server_tunnel);
  // Do some cleanup
  sandwich_io_owned_free(listener_io);
}

int main(int argc, char **argv) {

  const std::string server_hostname = "127.0.0.1";
  std::random_device rd;
  std::mt19937 rng(rd());
  std::uniform_int_distribution<int> distribution(1026, 65355);
  const uint16_t server_port = distribution(rng);
  std::vector<std::thread> threads;
  threads.push_back(std::thread(client_thread, server_hostname, server_port));
  threads.push_back(std::thread(server_thread, server_hostname, server_port));
  for (auto &thread : threads) {
    thread.join();
  }

  return 0;
}
