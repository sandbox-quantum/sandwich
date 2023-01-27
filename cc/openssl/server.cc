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
/// \brief
/// \file OpenSSL Sandwich server implementation.
///
/// \author thb-sb

#include "cc/openssl/server.h"

namespace saq::sandwich::openssl {

auto ServerContext::FromConfiguration(const ProtoConfiguration &config)
    -> ContextResult {
  if (!config.server().has_tls()) {
    return error::OpenSSLServerConfigurationError::kEmpty;
  }

  auto result = TLSContext::New(proto::Mode::MODE_SERVER);
  if (!result) {
    return result.GetError() >>
           error::OpenSSLServerConfigurationError::kSslCtxFailed;
  }

  auto tls_ctx = std::move(result.Get());

  const auto &tls_server = config.server().tls();

  if (tls_server.has_certificate()) {
    if (auto err = tls_ctx.AddOrSetCertificate(tls_server.certificate()); err) {
      return err >> error::OpenSSLServerConfigurationError::kCertificate;
    }
  }

  if (tls_server.has_private_key()) {
    if (auto err = tls_ctx.SetPrivateKey(tls_server.private_key()); err) {
      return err >> error::OpenSSLServerConfigurationError::kPrivateKey;
      return err;
    }
  }

  std::unique_ptr<ServerContext> ctx(
      new ServerContext(config, std::move(tls_ctx)));
  if (auto err = ctx->SetKems(config); err) {
    return err >> error::OpenSSLServerConfigurationError::kKem;
  }
  if (auto err = ctx->ApplyFlags(config); err) {
    return err >> error::OpenSSLServerConfigurationError::kFlags;
  }

  return std::unique_ptr<sandwich::Context>(ctx.release());
}

ServerContext::ServerContext(const ProtoConfiguration &config,
                             TLSContext &&tls_ctx)
    : openssl::Context{config, std::move(tls_ctx)} {}

ServerContext::~ServerContext() = default;

auto ServerContext::NewTunnel(std::unique_ptr<io::IO> ioint) -> TunnelResult {
  auto res{GetTLSContext().NewSession()};
  if (!res) {
    return res.GetError() >>
           error::OpenSSLServerConfigurationError::kSslFailed >>
           error::APIError::kTunnel;
  }
  auto tls_handle{std::move(res.Get())};

  ::BIO *bio = nullptr;
  if (const auto *meth = GetBIOMethod(); meth != nullptr) {
    bio = ::BIO_new(meth);
  } else {
    return error::SystemError::kMemory >>
           error::OpenSSLServerConfigurationError::kBioFailed >>
           error::APIError::kTunnel;
  }
  if (bio == nullptr) {
    return error::SystemError::kMemory >>
           error::OpenSSLServerConfigurationError::kBioFailed >>
           error::APIError::kTunnel;
  }

  return std::unique_ptr<sandwich::Tunnel>{
      new ServerTunnel{std::move(ioint), std::move(tls_handle), bio}};
}

/*******************************************************************************
 *                                  Tunnel                                     *
 ******************************************************************************/

auto ServerTunnel::Handshake() -> HandshakeState {
  if (GetState() == State::kHandshakeDone) {
    return HandshakeState::kDone;
  }

  auto &tls{GetTLS()};
  auto state{tls.GetState()};

  if (state == TLS_ST_OK) {
    SetState(State::kHandshakeDone);
    return HandshakeState::kDone;
  }

  auto err{::SSL_accept(tls)};
  if (err == 1) {
    SetState(State::kHandshakeDone);
    return HandshakeState::kDone;
  }
  err = tls.GetSSLError(err);
  switch (err) {
    case SSL_ERROR_WANT_READ: {
      SetState(State::kHandshakeInProgress);
      return HandshakeState::kWantRead;
    }
    case SSL_ERROR_WANT_WRITE: {
      SetState(State::kHandshakeInProgress);
      return HandshakeState::kWantWrite;
    }
    case SSL_ERROR_ZERO_RETURN: {
      SetState(State::kHandshakeInProgress);
      return HandshakeState::kInProgress;
    }
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_WANT_CONNECT: {
      SetState(State::kNotConnected);
      return HandshakeState::kInProgress;
    }
    default: {
      SetState(State::kError);
      return HandshakeState::kError;
    }
  }
}

} // end namespace saq::sandwich::openssl
