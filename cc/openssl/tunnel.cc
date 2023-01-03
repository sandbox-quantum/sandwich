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
/// \brief Tunnel implemented by OpeSSL, implementation
///
/// \author thb-sb

#include "cc/openssl/tunnel.h"

#include "cc/io/io.h"

namespace saq::sandwich::openssl {

namespace {

/// \brief OpenSSL error to another type of error.
///
/// \tparam ErrT Error type as return type.
///
/// \param err Error from OpenSSL.
///
/// \return The error type.
template <typename ErrT>
[[nodiscard]] auto OpenSSLErrorTo(int err) -> ErrT;

/// \brief OpenSSL error to io::IO::Error.
///
/// \param err OpenSSL error.
///
/// \return The most appropriate io::IO::Error.
template <>
[[nodiscard]] auto OpenSSLErrorTo<io::IO::Error>(const int err)
    -> io::IO::Error {
  switch (err) {
    using IOError = io::IO::Error;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE: {
      return IOError::kInProgress;
    }
    case SSL_ERROR_ZERO_RETURN: {
      return IOError::kClosed;
    }
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT: {
      return IOError::kInProgress;
    }
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
    default: {
      return IOError::kUnknown;
    }
  }
}

/// \brief OpenSSL error to sandwich::Tunnel::RecordError.
///
/// \param err OpenSSL error.
///
/// \return The most appropriate sandwich::Tunnel::RecordError.
template <>
[[nodiscard]] auto OpenSSLErrorTo<sandwich::Tunnel::RecordError>(const int err)
    -> sandwich::Tunnel::RecordError {
  switch (err) {
    using RecordError = sandwich::Tunnel::RecordError;
    case SSL_ERROR_WANT_READ: {
      return RecordError::kWantRead;
    }
    case SSL_ERROR_WANT_WRITE: {
      return RecordError::kWantWrite;
    }
    case SSL_ERROR_ZERO_RETURN: {
      return RecordError::kClosed;
    }

    case SSL_ERROR_SYSCALL: {
      if (errno == EPIPE) {
        return RecordError::kClosed;
      }
      return RecordError::kUnknown;
    }
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_SSL:
    default: {
      return RecordError::kUnknown;
    }
  }
}

} // end anonymous namespace

Tunnel::~Tunnel() = default;

Tunnel::Tunnel(std::unique_ptr<io::IO> ioint, TLSHandle tls,
               ::BIO *bio) noexcept
    : sandwich::Tunnel{std::move(ioint)}, tls_{std::move(tls)} {
  ::BIO_set_data(bio, this);
  ::BIO_set_init(bio, 1);
  ::SSL_set_bio(tls_, bio, bio);
}

auto Tunnel::Read(std::span<std::byte> buffer) -> RecordResult {
  if (buffer.size() > INT_MAX) {
    return {RecordError::kUnknown};
  }

  auto len{static_cast<int>(buffer.size())};
  auto err{::SSL_read(tls_, buffer.data(), len)};

  const auto new_state = CheckShutdownAndUpdateState();
  if (err > 0) {
    return {static_cast<std::size_t>(err)};
  }

  if (new_state == State::kBeingShutdown) {
    return {RecordError::kBeingShutdown};
  }
  if (new_state == State::kDisconnected) {
    return {RecordError::kClosed};
  }
  const auto ssl_err = tls_.GetSSLError(err);
  if ((ssl_err == SSL_ERROR_SYSCALL) && (err == 0)) {
    // Closed pipe: the remote peer closed the connection without
    // sending a shutdown alert. Therefore we consider the tunnel closed.
    SetState(State::kDisconnected);
    return {RecordError::kClosed};
  }

  return {OpenSSLErrorTo<sandwich::Tunnel::RecordError>(tls_.GetSSLError(err))};
}

auto Tunnel::Write(std::span<const std::byte> buffer) -> RecordResult {
  if (buffer.size() > INT_MAX) {
    return {RecordError::kUnknown};
  }

  auto len{static_cast<int>(buffer.size())};
  auto err{::SSL_write(tls_, buffer.data(), len)};

  const auto new_state = CheckShutdownAndUpdateState();
  if (err > 0) {
    return {static_cast<std::size_t>(err)};
  }

  if (new_state == State::kBeingShutdown) {
    return {RecordError::kBeingShutdown};
  }
  if (new_state == State::kDisconnected) {
    return {RecordError::kClosed};
  }

  const auto ssl_err = tls_.GetSSLError(err);
  if ((ssl_err == SSL_ERROR_SYSCALL) && ((errno == EPIPE) || (err == 0))) {
    // Closed pipe: the remote peer closed the connection without
    // sending a shutdown alert. Therefore we consider the tunnel closed.
    SetState(State::kDisconnected);
    return {RecordError::kClosed};
  }

  return {OpenSSLErrorTo<sandwich::Tunnel::RecordError>(tls_.GetSSLError(err))};
}

auto Tunnel::CheckShutdownAndUpdateState() -> State {
  const auto code = ::SSL_get_shutdown(tls_);
  if ((code & SSL_SENT_SHUTDOWN) != 0) {
    // According to the OpenSSL documentation:
    // > SSL_SENT_SHUTDOWN:
    // > […] the connection is being considered closed and the session is
    //       closed and correct.
    //
    // It means that if the flag `SSL_SENT_SHUTDOWN` is set, then the record
    // plane can be considered as closed (and not in the process of being
    // closed).
    return SetState(State::kDisconnected);
  }
  if ((code & SSL_RECEIVED_SHUTDOWN) != 0) {
    return SetState(State::kBeingShutdown);
  }
  return GetState();
}

auto Tunnel::Close() -> State {
  const auto state = GetState();
  if ((state != State::kBeingShutdown) && (state != State::kDisconnected)) {
    auto close_err = tls_.Close();
    if (close_err == 0) {
      // According to the documentation of `SSL_shutdown`, if 0 is returned,
      // we need to call `SSL_read`.
      ::SSL_read(tls_, nullptr, 0);
    }
    return SetState(State::kBeingShutdown);
  }
  if (state == State::kBeingShutdown) {
    // Two cases:
    //  * The remote peer calls `close`, therefore we need to answer to this
    //    signal.
    //  * This peer called `close` before, but the socket is non-blocking.
    //    A second call to `::SSL_shutdown` is needed.
    tls_.Close();
  }
  return CheckShutdownAndUpdateState();
}

} // end namespace saq::sandwich::openssl
