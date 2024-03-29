// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Unit tests for OpenSSL tunnels using the C frontend.
///
/// \author thb-sb

#include <array>
#include <thread>

#include "proto/api/v1/configuration.pb.h"
#include "proto/sandwich.pb.h"

#include "tools/cpp/runfiles/runfiles.h"

extern "C" {

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sandwich_c/sandwich.h"
#include "sandwich_c/tunnel.h"

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#endif

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

/// \brief Deleter for SandwichTunnelContext.
using SandwichTunnelContextDeleter =
    std::function<void(struct ::SandwichTunnelContext *)>;

/// \brief Create a Sandwich context for the client.
///
/// \param sw Top-level Sandwich context.
/// \param runfiles Bazel runfiles context.
///
/// \return A Sandwich context for the client.
auto CreateClientContext(const struct SandwichContext *sw,
                         std::unique_ptr<Runfiles> &runfiles)
    -> std::unique_ptr<struct ::SandwichTunnelContext,
                       SandwichTunnelContextDeleter> {
  auto config{
      NewTLSConfiguration(saq::sandwich::proto::Mode::MODE_CLIENT,
                          saq::sandwich::proto::api::v1::Implementation::
                              IMPL_OPENSSL3_OQS_PROVIDER)};

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
  const SandwichTunnelContextConfigurationSerialized serialized = {
      .src = encoded_configuration.data(),
      .n = encoded_configuration.size(),
  };
  const auto *err = ::sandwich_tunnel_context_new(sw, serialized, &ctx);
  sandwich_assert(err == nullptr);

  return {ctx, [](struct ::SandwichTunnelContext *c) {
            ::sandwich_tunnel_context_free(c);
          }};
}

/// \brief Create a Sandwich context for the server.
///
/// \param sw Top-level Sandwich context.
/// \param runfiles Bazel runfiles context.
///
/// \return A Sandwich context for the server.
auto CreateServerContext(const struct SandwichContext *sw,
                         std::unique_ptr<Runfiles> &runfiles)
    -> std::unique_ptr<struct ::SandwichTunnelContext,
                       SandwichTunnelContextDeleter> {
  auto config{
      NewTLSConfiguration(saq::sandwich::proto::Mode::MODE_SERVER,
                          saq::sandwich::proto::api::v1::Implementation::
                              IMPL_OPENSSL3_OQS_PROVIDER)};

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

  struct ::SandwichTunnelContext *ctx = nullptr;
  const SandwichTunnelContextConfigurationSerialized serialized = {
      .src = encoded_configuration.data(),
      .n = encoded_configuration.size(),
  };
  const auto *err = ::sandwich_tunnel_context_new(sw, serialized, &ctx);
  sandwich_assert(err == nullptr);

  return {ctx, [](struct ::SandwichTunnelContext *c) {
            ::sandwich_tunnel_context_free(c);
          }};
}

// --8<-- [start:cio_socket]

/// \brief Read from a socket.
///
/// This method is a SandwichIOReadFunction.
auto SandwichReadFromSocket(void *uarg, void *buf, const size_t count,
                            enum ::SandwichIOError *err) -> size_t {
  *err = SANDWICH_IOERROR_OK;

  const auto fd = static_cast<int>(reinterpret_cast<uintptr_t>(uarg));

  ssize_t r{0};

  do {
    if (r = ::read(fd, buf, count); r > -1) {
      return static_cast<size_t>(r);
    }
  } while ((r == -1) && (errno == EINTR));

  switch (errno) {
  case 0: {
    return *err = SANDWICH_IOERROR_OK, 0;
  }
  case EINPROGRESS:
  case EINTR: {
    return *err = SANDWICH_IOERROR_IN_PROGRESS, 0;
  }

  case EWOULDBLOCK:
#if EWOULDBLOCK != EAGAIN
  case EAGAIN:
#endif
  {
    return *err = SANDWICH_IOERROR_WOULD_BLOCK, 0;
  }

  case ENOTSOCK:
  case EPROTOTYPE:
  case EBADF: {
    return *err = SANDWICH_IOERROR_INVALID, 0;
  }
  case EACCES:
  case EPERM:
  case ETIMEDOUT:
  case ENETUNREACH:
  case ECONNREFUSED: {
    return *err = SANDWICH_IOERROR_REFUSED, 0;
  }

  default: {
    return *err = SANDWICH_IOERROR_UNKNOWN, 0;
  }
  }
}

/// \brief Write to a socket.
///
/// This method is a SandwichIOWriteFunction.
auto SandwichWriteToSocket(void *uarg, const void *buf, const size_t count,
                           enum ::SandwichIOError *err) -> size_t {
  *err = SANDWICH_IOERROR_OK;

  const auto fd = static_cast<int>(reinterpret_cast<uintptr_t>(uarg));

  ssize_t w{0};

  do {
    if (w = ::write(fd, buf, count); w > -1) {
      return static_cast<size_t>(w);
    }
  } while ((w == -1) && (errno == EINTR));

  switch (errno) {
  case 0: {
    return *err = SANDWICH_IOERROR_OK, 0;
  }
  case EINPROGRESS:
  case EINTR: {
    return *err = SANDWICH_IOERROR_WOULD_BLOCK, 0;
  }
  case ENOTSOCK:
  case EPROTOTYPE:
  case EBADF: {
    return *err = SANDWICH_IOERROR_INVALID, 0;
  }
  case EACCES:
  case EPERM:
  case ETIMEDOUT:
  case ENETUNREACH:
  case ECONNREFUSED: {
    return *err = SANDWICH_IOERROR_REFUSED, 0;
  }

  default: {
    return *err = SANDWICH_IOERROR_UNKNOWN, 0;
  }
  }
}

/// \brief Close a socket.
///
/// This method is a SandwichIOCloseFunction.
void CloseSocket(void *uarg) {
  const auto fd = static_cast<int>(reinterpret_cast<uintptr_t>(uarg));
  ::close(fd);
}

/// \brief Global IO interface for sockets.
constexpr struct ::SandwichIO SandwichSocketIO = {
    .read = SandwichReadFromSocket,
    .write = SandwichWriteToSocket,
    .uarg = nullptr};

/// \brief Global tunnel IO interface for sockets.
constexpr struct ::SandwichTunnelIO SandwichSocketTunnelIO {
  .base = SandwichSocketIO, .set_state = nullptr,
};
// --8<-- [end:cio_socket]

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
  sandwich_assert(err == NULL);
  sandwich_assert(state == SANDWICH_TUNNEL_HANDSHAKESTATE_WANT_READ);

  sandwich_assert(::sandwich_tunnel_state(client) ==
                  SANDWICH_TUNNEL_STATE_HANDSHAKE_IN_PROGRESS);

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
  sandwich_assert(err == NULL);
  sandwich_assert(state == SANDWICH_TUNNEL_HANDSHAKESTATE_WANT_READ);

  sandwich_assert(::sandwich_tunnel_state(server) ==
                  SANDWICH_TUNNEL_STATE_HANDSHAKE_IN_PROGRESS);

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
  const auto err{::sandwich_tunnel_handshake(client, &state)};
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
  const auto err{::sandwich_tunnel_handshake(server, &state)};
  sandwich_assert(err == NULL);
  sandwich_assert(state == SANDWICH_TUNNEL_HANDSHAKESTATE_DONE);

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

  const auto err{
      ::sandwich_tunnel_read(client, buffer.data(), buffer.size(), &r)};
  sandwich_assert(err == SANDWICH_TUNNEL_RECORDERROR_OK);
  sandwich_assert(r == kPongMsg.size());
  sandwich_assert(buffer == kPongMsg);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 8. Server tries to read something.
///
/// At this stage, the client hasn't written anything. The socket is
/// non-blocking, so the server MUST receive a `kWantRead`, and
/// `RecordResult::WouldBlock` MUST return true.
void ServerTriesRead(struct ::SandwichTunnel *server) {
  MsgBuffer buffer{};
  size_t r{0};

  const auto err{
      ::sandwich_tunnel_read(server, buffer.data(), buffer.size(), &r)};
  sandwich_assert(err == SANDWICH_TUNNEL_RECORDERROR_WANT_READ);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 9. Server closes the tunnel.
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

int main(int argc, char **argv) {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(
      Runfiles::CreateForTest(BAZEL_CURRENT_REPOSITORY, &error));
  sandwich_assert(runfiles != nullptr);

  std::unique_ptr<struct SandwichContext, SandwichContextDeleter> sw(
      ::sandwich_lib_context_new(),
      [](struct SandwichContext *sw) { ::sandwich_lib_context_free(sw); });

  auto client = CreateClientContext(&*sw, runfiles);
  auto server = CreateServerContext(&*sw, runfiles);

  // Create two connected sockets, to use with saq::sandwich::io::Socket.
  std::array<int, 2> fds{0};
#ifdef SOCK_NONBLOCK
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  auto err{::socketpair(PF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK, 0, fds.data())};
  sandwich_assert(err == 0);
#else
  auto err{::socketpair(PF_LOCAL, SOCK_STREAM, 0, fds.data())};
  sandwich_assert(err == 0);
  for (auto fd : fds) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    sandwich_assert(flags != -1);
    flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    sandwich_assert(flags != -1);
  }
#endif

  // Create I/O interfaces for client and server.

  struct ::SandwichTunnelIO client_io = SandwichSocketTunnelIO;
  client_io.base.uarg = reinterpret_cast<void *>(fds[0]);

  struct ::SandwichTunnelIO server_io = SandwichSocketTunnelIO;
  server_io.base.uarg = reinterpret_cast<void *>(fds[1]);

  // Create tunnels.
  auto client_tunnel = CreateTunnel(&*client, client_io,
                                    SandwichTunnelConfigurationVerifierEmpty);
  auto server_tunnel = CreateTunnel(&*server, server_io,
                                    SandwichTunnelConfigurationVerifierEmpty);

  // Client initiates the handshake.
  ClientInitiateHandshake(&*client_tunnel);

  // Server answers.
  ServerAnswerHandshake(&*server_tunnel);

  // Client is okay with the signature, the handshake is done.
  ClientCompleteHandshake(&*client_tunnel);

  // The server accesses to the record layer.
  ServerCompleteHandshake(&*server_tunnel);

  // Client sends « Ping ».
  ClientSendPing(&*client_tunnel);

  // Server receives « Ping » and sends « Pong ».
  ServerReadPingSendPong(&*server_tunnel);

  // Client receives « Pong ».
  ClientReadPong(&*client_tunnel);

  // Server tries to read, it triggers a `WANT_READ`, and WouldBlock returns
  // true.
  ServerTriesRead(&*server_tunnel);

  // Server closes the tunnel  by calling `Close`. It triggers a `SHUTDOWN`
  // TLS alert.
  ServerClosesTunnel(&*server_tunnel);

  CloseSocket(client_io.base.uarg);
  CloseSocket(server_io.base.uarg);
  return 0;
}
