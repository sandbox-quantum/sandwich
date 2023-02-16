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
/// \brief I/O layer implementation, using a socket, specification.
///
/// \author thb-sb

#include "cc/io/socket.h"

#include <chrono>
#include <forward_list>
#include <thread>
#include <utility>

extern "C" {

#ifdef __APPLE__
#include <fcntl.h>
#endif
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

} // end extern "C"

#ifndef SOL_TCP
#ifndef IPPROTO_TCP
#error "Failed to find SOL_TCP or IPPROTO_TCP"
#endif
#define SOL_TCP IPPROTO_TCP
#endif

namespace saq::sandwich::io {

auto FileDescriptor::New(const int fdesc)
    -> Result<FileDescriptor, error::Error> {
  if (fdesc != kInvalidFd) {
    return FileDescriptor{fdesc};
  }
  return error::SocketError::kBadFd;
}

FileDescriptor::FileDescriptor(int fdesc) noexcept : fd_{fdesc} {}

FileDescriptor::FileDescriptor(FileDescriptor &&other) noexcept
    : fd_{other.fd_} {
  other.fd_ = kInvalidFd;
}

auto FileDescriptor::operator=(FileDescriptor &&other) noexcept
    -> FileDescriptor & {
  if (fd_ != kInvalidFd) {
    ::close(fd_);
    fd_ = kInvalidFd;
  }
  std::swap(fd_, other.fd_);
  return *this;
}

FileDescriptor::~FileDescriptor() noexcept {
  if (fd_ != kInvalidFd) {
    ::close(fd_);
    fd_ = kInvalidFd;
  }
}

namespace {

/// \brief Returns the appropriate IO::Error depending on a value returned
///        by SO_ERROR.
///
/// \param soerr Socket error
///
/// \return The most appropriate IO::Error
[[nodiscard]] auto SocketErrorToIOError(int soerr) -> IO::Error {
  switch (soerr) {
    case 0: {
      return IO::Error::kOk;
    }
    case EINPROGRESS:
    case EINTR: {
      return IO::Error::kInProgress;
    }

    // case EAGAIN, EAGAIN == EWOULDBLOCK
    case EWOULDBLOCK: {
      return IO::Error::kWouldBlock;
    }

    case ENOTSOCK:
    case EPROTOTYPE:
    case EBADF: {
      return IO::Error::kInvalid;
    }

    case EPIPE: {
      return IO::Error::kClosed;
    }

    case EACCES:
    case EPERM:
    case ETIMEDOUT:
    case ENETUNREACH:
    case ECONNREFUSED: {
      return IO::Error::kRefused;
    }
    default: {
      return IO::Error::kUnknown;
    }
  }
}

/// \brief Create a non-blocking socket.
///
/// \param af_inet Address family (AF_INET or AF_INET6)
///
/// \return The created socket, or an error.
[[nodiscard, maybe_unused]] auto NewNonBlockingSocket(const int af_inet)
    -> Result<FileDescriptor, error::Error> {
#ifdef SOCK_NONBLOCK
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  auto sock = ::socket(af_inet, SOCK_STREAM | SOCK_NONBLOCK, 0);
#else
  auto sock = ::socket(af_inet, SOCK_STREAM, 0);
  if (sock > 0) {
    const int flags = ::fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
      ::close(sock);
      return error::SocketError::kSetsockoptFailed;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
      ::close(sock);
      return error::SocketError::kSetsockoptFailed;
    }
  }
#endif
  if (sock < 0) {
    return error::SocketError::kCreationFailed;
  }
  int opt = 1;
  ::socklen_t len = sizeof(opt);
  ::setsockopt(sock, SOL_TCP, TCP_NODELAY, &opt, len);
  auto res = FileDescriptor::New(sock);
  if (res) {
    return std::move(res.Get());
  }
  return res.GetError();
}

/// \brief Resolve a network address.
///
/// \param[in] netaddr Network address to resolve.
///
/// \return The resolved network address, or an error code.
[[nodiscard, maybe_unused]] auto ResolveAddress(const std::string &netaddr)
    -> Result<std::forward_list<NetworkAddress>, error::Error> {
  if (netaddr.empty()) {
    return error::SocketError::kBadNetaddr;
  }
  struct ::addrinfo hints = {.ai_family = PF_UNSPEC,
                             .ai_socktype = SOCK_STREAM};
  struct ::addrinfo *tmp = nullptr;
  if (::getaddrinfo(netaddr.c_str(), nullptr, &hints, &tmp) != 0) {
    return error::SocketError::kNetaddrUnknown;
  }
  std::unique_ptr<struct ::addrinfo, std::function<void(struct ::addrinfo *)>>
      list(tmp, [](struct ::addrinfo *list) {
        if (list != nullptr) {
          ::freeaddrinfo(list);
        }
      });

  std::forward_list<NetworkAddress> results{};
  auto ins = results.before_begin();
  // NOLINTNEXTLINE
  for (const auto *candidate{list.get()}; candidate != nullptr;
       candidate = candidate->ai_next) {
    NetworkAddress addr{};
    if (candidate->ai_family == AF_INET) {
      /// NOLINTNEXTLINE
      addr.addr.i4 =
          *reinterpret_cast<struct ::sockaddr_in *>(candidate->ai_addr);
    } else if (candidate->ai_family == AF_INET6) {
      /// NOLINTNEXTLINE
      addr.addr.i6 =
          *reinterpret_cast<struct ::sockaddr_in6 *>(candidate->ai_addr);
    } else {
      continue;
    }
    addr.ai_family = candidate->ai_family;
    addr.len = candidate->ai_addrlen;
    ins = results.insert_after(ins, addr);
  }

  return {results};
}

} // end anonymous namespace

void Socket::Close() {
  ::close(fd_.Release());
}

auto Socket::FromFd(int fdesc) -> Result<std::unique_ptr<IO>, error::Error> {
  if (fdesc <= FileDescriptor::kInvalidFd) {
    return error::SocketError::kBadFd;
  }

  struct ::stat statbuf {};
  if (::fstat(fdesc, &statbuf) != 0) {
    return error::SocketError::kFstatFailed;
  }
  // NOLINTNEXTLINE
  if (!S_ISSOCK(statbuf.st_mode)) {
    return error::SocketError::kNotSock;
  }

  auto res = FileDescriptor::New(fdesc);
  if (!res) {
    return res.GetError();
  }
  return FromFd(std::move(res.Get()));
}

auto Socket::FromFd(FileDescriptor fdesc)
    -> Result<std::unique_ptr<IO>, error::Error> {
  NetworkAddress addr{};
  // NOLINTNEXTLINE
  addr.len = sizeof(addr.addr.i6);
  // NOLINTNEXTLINE
  if (::getsockname(fdesc, reinterpret_cast<struct ::sockaddr *>(&addr.addr),
                    &addr.len) != 0) {
    return error::SocketError::kGetsocknameFailed;
  }
  // NOLINTNEXTLINE
  addr.ai_family = reinterpret_cast<struct ::sockaddr *>(&addr.addr)->sa_family;
  return std::unique_ptr<IO>{new Socket{std::move(fdesc), addr}};
}

Socket::Socket(FileDescriptor sock, const NetworkAddress &addr) noexcept
    : fd_{std::move(sock)}, addr_{addr} {}

Socket::Socket(Socket &&other) noexcept
    : IO{std::forward<IO>(other)},
      fd_{std::move(other.fd_)},
      addr_{other.addr_} {}

auto Socket::operator=(Socket &&other) noexcept -> Socket & {
  IO::operator=(std::forward<IO>(other));
  ::close(fd_.Release());
  std::swap(fd_, other.fd_);
  return *this;
}

Socket::~Socket() = default;

auto Socket::GetSocketError() const noexcept -> Result<int, error::Error> {
  int err = 0;
  ::socklen_t len = sizeof(err);

  if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
    return error::SocketError::kSetsockoptFailed;
  }
  if (len != sizeof(err)) {
    return error::SocketError::kSetsockoptFailed;
  }
  return err;
}

auto Socket::Read(std::span<std::byte> buffer,
                  [[maybe_unused]] const tunnel::State state) -> OpResult {
  SetError(Error::kOk);

  ssize_t rbytes = -1;
  do {
    if (rbytes = ::recv(fd_, buffer.data(), buffer.size(), MSG_NOSIGNAL);
        rbytes > -1) {
      return {.count = static_cast<std::size_t>(rbytes), .err = Error::kOk};
    }
  } while ((rbytes == -1) && (errno == EINTR));

  return {.count = 0, .err = SetError(SocketErrorToIOError(errno))};
}

auto Socket::Write(std::span<const std::byte> buffer,
                   [[maybe_unused]] const tunnel::State state) -> OpResult {
  SetError(Error::kOk);

  ssize_t wbytes = -1;
  do {
    if (wbytes = ::send(fd_, buffer.data(), buffer.size(), MSG_NOSIGNAL);
        wbytes > -1) {
      return {.count = static_cast<std::size_t>(wbytes), .err = Error::kOk};
    }
  } while ((wbytes == -1) && (errno == EINTR));

  return {.count = 0, .err = SetError(SocketErrorToIOError(errno))};
}

auto Socket::Poll(int events, std::optional<int> timeout)
    -> Result<int, Error> {
  SetError(Error::kOk);

  struct ::pollfd pfd = {
      .fd = fd_.Get(), .events = static_cast<int16_t>(events), .revents = 0};

  int ret = -1;
  do {
    ret = ::poll(&pfd, 1, timeout.value_or(-1));
  } while ((ret == -1) && (errno == EINTR));
  if (ret == 0) {
    return static_cast<int>(0);
  }
  if (ret < 0) {
    return SetError(SocketErrorToIOError(errno));
  }
  return pfd.revents;
}

namespace {

/// \brief Set the port to a Network address, depending on its family.
///
/// \param[in,out] address Address.
/// \param netport Port.
///
/// \return Error::ERROR_OK if success, else an error code.
[[nodiscard, maybe_unused]] auto AddressSetPort(NetworkAddress &address,
                                                const uint16_t netport)
    -> error::Error {
  if (address.ai_family == AF_INET) {
    // NOLINTNEXTLINE
    address.addr.i4.sin_port = htons(netport);
  } else if (address.ai_family == AF_INET6) {
    // NOLINTNEXTLINE
    address.addr.i6.sin6_port = htons(netport);
  } else {
    return error::SocketError::kInvalidAiFamily;
  }
  return error::Ok;
}

} // end anonymous namespace

} // end namespace saq::sandwich::io
